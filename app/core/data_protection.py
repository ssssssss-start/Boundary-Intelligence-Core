"""Application-level data protection for sensitive anti-fraud records.

MongoDB encryption at rest is still recommended for production, but it is not
enough on its own: database administrators, snapshots, exports and accidental
collection reads should not expose user-provided evidence.  This module adds a
small envelope-encryption layer at the application boundary and a transparent
Mongo collection proxy used by the two Mongo clients in this project.

The preferred backend is AES-GCM from ``cryptography``.  A SHA-256/HMAC stream
fallback is kept only for constrained development environments where the
optional dependency is unavailable; production deployments must install
``cryptography`` and set ``ANTI_FRAUD_ENCRYPTION_REQUIRED=1``.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import logging
import os
import secrets
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:  # pragma: no cover - exercised when the optional dependency is present
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - local minimal environments use fallback
    AESGCM = None

    class InvalidTag(Exception):
        pass


LOGGER = logging.getLogger(__name__)

ENVELOPE_PREFIX = "afenc1"
ENVELOPE_PARTS = 4
DEFAULT_KEY_ID = "v1"
KEY_ENV_NAMES = (
    "ANTI_FRAUD_DATA_ENCRYPTION_KEY",
    "ANTI_FRAUD_ENCRYPTION_KEY",
    "DATA_ENCRYPTION_KEY",
)


class DataProtectionError(RuntimeError):
    """Base class for data-protection failures."""


class EncryptionConfigurationError(DataProtectionError):
    """Raised when encryption is required but no usable key is configured."""


class InvalidEncryptedValue(DataProtectionError):
    """Raised when an encrypted value is malformed or fails authentication."""


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def encryption_required() -> bool:
    """Whether missing crypto configuration should fail closed.

    Local/demo installs remain backwards compatible until a key is supplied.
    Production and strict deployments must explicitly configure a key.
    """

    environment = os.getenv("ANTI_FRAUD_ENV", os.getenv("ENVIRONMENT", "")).strip().lower()
    return _env_bool(
        "ANTI_FRAUD_ENCRYPTION_REQUIRED",
        _env_bool("ANTI_FRAUD_SECURITY_STRICT", False) or environment in {"prod", "production"},
    )


def encryption_enabled() -> bool:
    return _env_bool("ANTI_FRAUD_DATA_ENCRYPTION_ENABLED", True)


def generate_encryption_key() -> str:
    """Return a URL-safe 256-bit key suitable for an environment variable."""

    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    text = str(value or "").strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _derive_key(raw: str) -> bytes:
    """Normalize a human/env supplied key into a 32-byte key.

    Explicit ``hex:`` and ``base64:`` prefixes are supported.  Unprefixed
    values accept either URL-safe base64 or a passphrase which is stretched
    with SHA-256.  This keeps deployment configuration ergonomic while making
    the actual cipher key a fixed length.
    """

    value = str(raw or "").strip()
    if not value:
        raise EncryptionConfigurationError("加密密钥不能为空")
    if value.startswith("hex:"):
        try:
            decoded = bytes.fromhex(value[4:])
        except ValueError as exc:
            raise EncryptionConfigurationError("ANTI_FRAUD_DATA_ENCRYPTION_KEY 的 hex 格式无效") from exc
    elif value.startswith("base64:"):
        try:
            decoded = _b64decode(value[7:])
        except Exception as exc:
            raise EncryptionConfigurationError("ANTI_FRAUD_DATA_ENCRYPTION_KEY 的 base64 格式无效") from exc
    else:
        decoded = b""
        try:
            candidate = _b64decode(value)
            if len(candidate) >= 16:
                decoded = candidate
        except Exception:
            decoded = b""
        if not decoded:
            decoded = value.encode("utf-8")
    if len(decoded) < 16:
        raise EncryptionConfigurationError("加密密钥至少需要 16 字节")
    return hashlib.sha256(decoded).digest()


def _parse_keyring() -> Dict[str, bytes]:
    """Load current and previous keys from environment variables.

    ``ANTI_FRAUD_DATA_ENCRYPTION_KEYS`` accepts JSON (``{"v1":"..."}``) or
    comma-separated ``key_id:key`` entries.  The current key can also be set
    independently through ``ANTI_FRAUD_DATA_ENCRYPTION_KEY``.
    """

    keyring: Dict[str, bytes] = {}
    raw_ring = os.getenv("ANTI_FRAUD_DATA_ENCRYPTION_KEYS", "").strip()
    if raw_ring:
        parsed: Any = None
        try:
            parsed = json.loads(raw_ring)
        except Exception:
            parsed = None
        entries: List[Tuple[str, str]] = []
        if isinstance(parsed, dict):
            entries.extend((str(key), str(value)) for key, value in parsed.items())
        else:
            for item in raw_ring.split(","):
                if ":" not in item:
                    continue
                key_id, value = item.split(":", 1)
                if key_id.strip() and value.strip():
                    entries.append((key_id.strip(), value.strip()))
        for key_id, value in entries:
            keyring[key_id] = _derive_key(value)

    current = next((os.getenv(name, "").strip() for name in KEY_ENV_NAMES if os.getenv(name, "").strip()), "")
    if current:
        keyring[os.getenv("ANTI_FRAUD_DATA_ENCRYPTION_KEY_ID", DEFAULT_KEY_ID).strip() or DEFAULT_KEY_ID] = _derive_key(current)
    return keyring


def _keyring_or_raise() -> Dict[str, bytes]:
    if not encryption_enabled():
        return {}
    keyring = _parse_keyring()
    if keyring:
        return keyring
    if encryption_required():
        raise EncryptionConfigurationError(
            "已要求数据加密，但未配置 ANTI_FRAUD_DATA_ENCRYPTION_KEY(S)"
        )
    return {}


def encryption_status() -> Dict[str, Any]:
    """Return safe operational status without exposing key material."""

    keyring = _parse_keyring()
    current_id = os.getenv("ANTI_FRAUD_DATA_ENCRYPTION_KEY_ID", DEFAULT_KEY_ID).strip() or DEFAULT_KEY_ID
    return {
        "enabled": encryption_enabled(),
        "required": encryption_required(),
        "configured": bool(keyring),
        "current_key_id": current_id if current_id in keyring else None,
        "known_key_ids": sorted(keyring),
        "backend": "aes-gcm" if AESGCM is not None else "development-hmac-stream",
        "production_ready": bool(AESGCM is not None and keyring),
    }


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return {"__af_type__": "datetime", "value": value.isoformat()}
    if isinstance(value, bytes):
        return {"__af_type__": "bytes", "value": _b64encode(value)}
    if isinstance(value, set):
        return {"__af_type__": "set", "value": list(value)}
    if hasattr(value, "__str__"):
        return {"__af_type__": "str", "value": str(value)}
    raise TypeError(f"Unsupported value for encryption: {type(value)!r}")


def _json_restore(value: Any) -> Any:
    if isinstance(value, list):
        return [_json_restore(item) for item in value]
    if not isinstance(value, dict) or "__af_type__" not in value:
        if isinstance(value, dict):
            return {key: _json_restore(item) for key, item in value.items()}
        return value
    kind = value.get("__af_type__")
    if kind == "datetime":
        try:
            return datetime.fromisoformat(str(value.get("value")))
        except Exception:
            return value.get("value")
    if kind == "bytes":
        try:
            return _b64decode(str(value.get("value")))
        except Exception:
            return b""
    if kind == "set":
        return set(_json_restore(item) for item in value.get("value", []))
    return value.get("value")


def _aad_bytes(aad: str) -> bytes:
    return str(aad or "").encode("utf-8")


def _fallback_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    chunks = []
    counter = 0
    while sum(len(item) for item in chunks) < length:
        chunks.append(hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest())
        counter += 1
    return b"".join(chunks)[:length]


def _fallback_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    stream = _fallback_keystream(key, nonce, len(plaintext))
    ciphertext = bytes(left ^ right for left, right in zip(plaintext, stream))
    tag = hmac.new(key, aad + nonce + ciphertext, hashlib.sha256).digest()[:16]
    return nonce + tag + ciphertext


def _fallback_decrypt(key: bytes, encoded: bytes, aad: bytes) -> bytes:
    if len(encoded) < 32:
        raise InvalidEncryptedValue("加密数据长度无效")
    nonce, tag, ciphertext = encoded[:16], encoded[16:32], encoded[32:]
    expected = hmac.new(key, aad + nonce + ciphertext, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected):
        raise InvalidTag("加密数据认证失败")
    stream = _fallback_keystream(key, nonce, len(ciphertext))
    return bytes(left ^ right for left, right in zip(ciphertext, stream))


def is_encrypted(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(ENVELOPE_PREFIX + ".")


def encrypt_value(value: Any, *, aad: str = "") -> Any:
    """Encrypt a JSON-compatible value, preserving its type on decrypt."""

    if value is None or is_encrypted(value) or not encryption_enabled():
        return value
    keyring = _keyring_or_raise()
    if not keyring:
        return value
    key_id = os.getenv("ANTI_FRAUD_DATA_ENCRYPTION_KEY_ID", DEFAULT_KEY_ID).strip() or DEFAULT_KEY_ID
    key = keyring.get(key_id)
    if key is None:  # keyring may contain only old keys
        key_id, key = next(iter(keyring.items()))
    plaintext = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=_json_default).encode("utf-8")
    aad_bytes = _aad_bytes(aad)
    if AESGCM is not None:
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(key).encrypt(nonce, plaintext, aad_bytes)
        algorithm = "aesgcm"
        encoded = _b64encode(nonce + encrypted)
    else:
        nonce = secrets.token_bytes(16)
        algorithm = "hmacstream"
        encoded = _b64encode(_fallback_encrypt(key, nonce, plaintext, aad_bytes))
    return f"{ENVELOPE_PREFIX}.{key_id}.{algorithm}.{encoded}"


def decrypt_value(value: Any, *, aad: str = "") -> Any:
    if not is_encrypted(value):
        return value
    parts = value.split(".", 3)
    if len(parts) != ENVELOPE_PARTS or parts[0] != ENVELOPE_PREFIX:
        raise InvalidEncryptedValue("加密信封格式无效")
    _, key_id, algorithm, encoded = parts
    keyring = _keyring_or_raise()
    if not keyring:
        raise EncryptionConfigurationError("无法解密：未配置数据加密密钥")
    try:
        raw = _b64decode(encoded)
    except Exception as exc:
        raise InvalidEncryptedValue("加密信封编码无效") from exc
    keys = []
    if key_id in keyring:
        keys.append(keyring[key_id])
    keys.extend(key for known_id, key in keyring.items() if known_id != key_id)
    last_error: Optional[Exception] = None
    for key in keys:
        try:
            if algorithm == "aesgcm":
                if AESGCM is None or len(raw) < 13:
                    continue
                plaintext = AESGCM(key).decrypt(raw[:12], raw[12:], _aad_bytes(aad))
            elif algorithm == "hmacstream":
                plaintext = _fallback_decrypt(key, raw, _aad_bytes(aad))
            else:
                raise InvalidEncryptedValue("不支持的加密算法")
            return _json_restore(json.loads(plaintext.decode("utf-8")))
        except (InvalidTag, InvalidEncryptedValue, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_error = exc
            continue
    raise InvalidEncryptedValue("加密数据认证失败或密钥不可用") from last_error


def encrypt_text(value: str, *, aad: str = "") -> str:
    result = encrypt_value(str(value or ""), aad=aad)
    return str(result)


def decrypt_text(value: Any, *, aad: str = "") -> str:
    result = decrypt_value(value, aad=aad)
    return "" if result is None else str(result)


# Fields intentionally kept searchable/indexable (IDs, status, timestamps) are
# omitted.  Values under these names are encrypted as a whole, including nested
# dictionaries/lists, so raw user evidence cannot leak through a new subfield.
PROTECTED_FIELDS: Dict[str, frozenset[str]] = {
    "chat_message": frozenset({"text", "rewritten_query", "risk_summary", "image_urls", "emotion", "voice_transcript", "turn_memory"}),
    "anti_fraud_case_state": frozenset({"slots", "route_memory", "route_context", "slot_memory", "exposure_memory", "current_unsafe_memory", "scam_memory", "risk_memory", "intervention_memory", "resolution_memory", "education_memory", "memory_summary", "risk_decay", "user_situation", "case_context_label"}),
    "anti_fraud_session_state": frozenset({"pending_question", "last_route_decision"}),
    "anti_fraud_case_event": frozenset({"event_payload"}),
    "report_tickets": frozenset({"content", "raw_user_content", "amount", "contact", "note", "evidence", "attachments", "reporter", "submitter", "source_text", "handler_note", "report_intel"}),
    "report_analysis_drafts": frozenset({"content", "raw_user_content", "amount", "contact", "note", "evidence", "attachments", "source_text", "report_intel", "analysis", "draft"}),
    "scam_intake_submissions": frozenset({"content", "source_text", "submitter", "contact", "metadata", "payload"}),
    "scam_draft_packages": frozenset({"content", "source_text", "submitter", "metadata", "draft", "package", "enrichment"}),
    "scam_review_tasks": frozenset({"review_notes", "metadata", "enrichment", "payload"}),
    "scam_review_comments": frozenset({"comment", "content", "metadata"}),
    "scam_publish_packages": frozenset({"package", "content", "metadata"}),
    "scam_publish_versions": frozenset({"package", "content", "metadata"}),
    "scam_rollback_records": frozenset({"reason", "snapshot", "metadata"}),
    "audit_logs": frozenset({"payload"}),
    "web_fallback_cache": frozenset({"query", "response", "content", "body", "metadata"}),
}

RETENTION_ENV_BY_COLLECTION = {
    "chat_message": "ANTI_FRAUD_RETENTION_CHAT_DAYS",
    "anti_fraud_case_state": "ANTI_FRAUD_RETENTION_CASE_DAYS",
    "anti_fraud_session_state": "ANTI_FRAUD_RETENTION_SESSION_DAYS",
    "anti_fraud_case_event": "ANTI_FRAUD_RETENTION_EVENT_DAYS",
    "report_tickets": "ANTI_FRAUD_RETENTION_REPORT_DAYS",
    "report_analysis_drafts": "ANTI_FRAUD_RETENTION_DRAFT_DAYS",
    "audit_logs": "ANTI_FRAUD_RETENTION_AUDIT_DAYS",
    "web_fallback_cache": "ANTI_FRAUD_RETENTION_CACHE_DAYS",
}
DEFAULT_RETENTION_DAYS = {
    "chat_message": 90,
    "anti_fraud_case_state": 90,
    "anti_fraud_session_state": 90,
    "anti_fraud_case_event": 180,
    "report_tickets": 730,
    "report_analysis_drafts": 7,
    "audit_logs": 365,
    "web_fallback_cache": 30,
}


def retention_days(collection_name: str) -> Optional[int]:
    env_name = RETENTION_ENV_BY_COLLECTION.get(collection_name)
    if not env_name:
        return None
    raw = os.getenv(env_name)
    try:
        days = int(raw) if raw is not None else DEFAULT_RETENTION_DAYS.get(collection_name, 0)
    except (TypeError, ValueError):
        days = DEFAULT_RETENTION_DAYS.get(collection_name, 0)
    return max(days, 0) or None


def _transform_field_value(value: Any, *, collection: str, field: str, decrypt: bool) -> Any:
    aad = f"{collection}.{field}"
    if decrypt:
        try:
            return decrypt_value(value, aad=aad)
        except DataProtectionError:
            # A legacy plaintext document must remain readable during migration;
            # malformed ciphertext is left untouched for the migration scanner.
            LOGGER.warning("无法解密 %s.%s 字段，保留原值", collection, field)
            return value
    try:
        return encrypt_value(value, aad=aad)
    except DataProtectionError:
        if encryption_required():
            raise
        return value


def protect_document(collection: str, document: Mapping[str, Any], *, decrypt: bool = False) -> Dict[str, Any]:
    """Encrypt/decrypt configured fields in a document without mutating it."""

    if not isinstance(document, Mapping):
        return dict(document or {})
    fields = PROTECTED_FIELDS.get(collection, frozenset())
    result: Dict[str, Any] = {}
    encrypted_fields: List[str] = []
    for key, value in document.items():
        key_text = str(key)
        if key_text in fields:
            result[key] = _transform_field_value(value, collection=collection, field=key_text, decrypt=decrypt)
            if not decrypt and is_encrypted(result[key]):
                encrypted_fields.append(key_text)
        elif isinstance(value, Mapping):
            result[key] = protect_document(collection, value, decrypt=decrypt)
        elif isinstance(value, list) and key_text not in fields:
            result[key] = [
                protect_document(collection, item, decrypt=decrypt) if isinstance(item, Mapping) else item
                for item in value
            ]
        else:
            result[key] = value
    if not decrypt and encrypted_fields:
        result.setdefault("data_encryption", {
            "version": ENVELOPE_PREFIX,
            "key_id": os.getenv("ANTI_FRAUD_DATA_ENCRYPTION_KEY_ID", DEFAULT_KEY_ID).strip() or DEFAULT_KEY_ID,
            "fields": sorted(encrypted_fields),
            "encrypted_at": datetime.now(timezone.utc),
        })
    return result


def protect_update(collection: str, update: Mapping[str, Any]) -> Dict[str, Any]:
    """Protect values inside a Mongo update document."""

    if not isinstance(update, Mapping):
        return dict(update or {})
    fields = PROTECTED_FIELDS.get(collection, frozenset())
    result: Dict[str, Any] = {}
    for operator, values in update.items():
        if not isinstance(values, Mapping) or not str(operator).startswith("$"):
            result[operator] = protect_document(collection, values) if isinstance(values, Mapping) else values
            continue
        transformed: Dict[str, Any] = {}
        for path, value in values.items():
            field = str(path).split(".")[-1]
            if field in fields:
                transformed[path] = _transform_field_value(value, collection=collection, field=field, decrypt=False)
            elif isinstance(value, Mapping):
                transformed[path] = protect_document(collection, value)
            elif isinstance(value, list):
                transformed[path] = [protect_document(collection, item) if isinstance(item, Mapping) else item for item in value]
            else:
                transformed[path] = value
        result[operator] = transformed
    return result


def add_retention_metadata(collection: str, document: Mapping[str, Any]) -> Dict[str, Any]:
    result = dict(document)
    days = retention_days(collection)
    if days is not None and "data_retention_expires_at" not in result:
        result["data_retention_expires_at"] = datetime.now(timezone.utc) + timedelta(days=days)
        result["data_retention_policy"] = {"days": days, "source": "application"}
    return result


def decrypt_document(collection: str, document: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if document is None:
        return None
    return protect_document(collection, document, decrypt=True)


class ProtectedCursor:
    """Cursor adapter which decrypts documents as they leave MongoDB."""

    def __init__(self, cursor: Any, collection: str):
        self._cursor = cursor
        self._collection = collection

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        for item in self._cursor:
            yield decrypt_document(self._collection, item) or {}

    def __next__(self) -> Dict[str, Any]:
        return decrypt_document(self._collection, next(self._cursor)) or {}

    def sort(self, *args: Any, **kwargs: Any) -> "ProtectedCursor":
        self._cursor = self._cursor.sort(*args, **kwargs)
        return self

    def limit(self, *args: Any, **kwargs: Any) -> "ProtectedCursor":
        self._cursor = self._cursor.limit(*args, **kwargs)
        return self

    def skip(self, *args: Any, **kwargs: Any) -> "ProtectedCursor":
        self._cursor = self._cursor.skip(*args, **kwargs)
        return self

    def batch_size(self, *args: Any, **kwargs: Any) -> "ProtectedCursor":
        self._cursor = self._cursor.batch_size(*args, **kwargs)
        return self

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cursor, name)


class ProtectedCollection:
    """Transparent field-protecting wrapper around a PyMongo collection."""

    def __init__(self, collection: Any, name: Optional[str] = None):
        self._collection = collection
        self.name = name or getattr(collection, "name", "")

    def insert_one(self, document: Mapping[str, Any], *args: Any, **kwargs: Any) -> Any:
        protected = add_retention_metadata(self.name, protect_document(self.name, document))
        return self._collection.insert_one(protected, *args, **kwargs)

    def insert_many(self, documents: Iterable[Mapping[str, Any]], *args: Any, **kwargs: Any) -> Any:
        protected = [add_retention_metadata(self.name, protect_document(self.name, item)) for item in documents]
        return self._collection.insert_many(protected, *args, **kwargs)

    def replace_one(self, filter: Mapping[str, Any], replacement: Mapping[str, Any], *args: Any, **kwargs: Any) -> Any:
        protected = add_retention_metadata(self.name, protect_document(self.name, replacement))
        return self._collection.replace_one(filter, protected, *args, **kwargs)

    def update_one(self, filter: Mapping[str, Any], update: Mapping[str, Any], *args: Any, **kwargs: Any) -> Any:
        return self._collection.update_one(filter, protect_update(self.name, update), *args, **kwargs)

    def update_many(self, filter: Mapping[str, Any], update: Mapping[str, Any], *args: Any, **kwargs: Any) -> Any:
        return self._collection.update_many(filter, protect_update(self.name, update), *args, **kwargs)

    def find_one_and_update(self, filter: Mapping[str, Any], update: Mapping[str, Any], *args: Any, **kwargs: Any) -> Any:
        result = self._collection.find_one_and_update(filter, protect_update(self.name, update), *args, **kwargs)
        return decrypt_document(self.name, result)

    def find_one_and_replace(self, filter: Mapping[str, Any], replacement: Mapping[str, Any], *args: Any, **kwargs: Any) -> Any:
        result = self._collection.find_one_and_replace(filter, add_retention_metadata(self.name, protect_document(self.name, replacement)), *args, **kwargs)
        return decrypt_document(self.name, result)

    def find_one_and_delete(self, *args: Any, **kwargs: Any) -> Any:
        return decrypt_document(self.name, self._collection.find_one_and_delete(*args, **kwargs))

    def find_one(self, *args: Any, **kwargs: Any) -> Any:
        return decrypt_document(self.name, self._collection.find_one(*args, **kwargs))

    def find(self, *args: Any, **kwargs: Any) -> ProtectedCursor:
        return ProtectedCursor(self._collection.find(*args, **kwargs), self.name)

    def aggregate(self, *args: Any, **kwargs: Any) -> ProtectedCursor:
        return ProtectedCursor(self._collection.aggregate(*args, **kwargs), self.name)

    def bulk_write(self, operations: Sequence[Any], *args: Any, **kwargs: Any) -> Any:
        transformed = []
        for operation in operations:
            item = copy.copy(operation)
            if hasattr(item, "_doc"):
                doc = item._doc
                if isinstance(doc, Mapping) and any(str(key).startswith("$") for key in doc):
                    item._doc = protect_update(self.name, doc)
                elif isinstance(doc, Mapping):
                    item._doc = add_retention_metadata(self.name, protect_document(self.name, doc))
            transformed.append(item)
        return self._collection.bulk_write(transformed, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._collection, name)


class ProtectedDatabase:
    """Database adapter returning :class:`ProtectedCollection` instances."""

    def __init__(self, database: Any):
        self._database = database

    def __getitem__(self, name: str) -> ProtectedCollection:
        return ProtectedCollection(self._database[name], name)

    def get_collection(self, name: str, *args: Any, **kwargs: Any) -> ProtectedCollection:
        return ProtectedCollection(self._database.get_collection(name, *args, **kwargs), name)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._database, name)


def retention_collections() -> Dict[str, int]:
    return {name: days for name in RETENTION_ENV_BY_COLLECTION if (days := retention_days(name)) is not None}


def encrypted_fields_for_collection(collection: str) -> List[str]:
    return sorted(PROTECTED_FIELDS.get(collection, frozenset()))


def rotate_value(value: Any, *, aad: str = "") -> Any:
    """Re-encrypt one envelope with the configured current key."""

    if not is_encrypted(value):
        return value
    plaintext = decrypt_value(value, aad=aad)
    return encrypt_value(plaintext, aad=aad)

