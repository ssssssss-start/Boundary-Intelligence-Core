import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict

from fastapi import HTTPException, Request

from app.clients.mongo_business_utils import get_business_mongo_tool, write_audit_log
from app.core.security import env_bool, is_weak_password


SESSION_COOKIE = "anti_fraud_admin_session"
SESSION_HOURS = int(os.getenv("ANTI_FRAUD_ADMIN_SESSION_HOURS", "8") or 8)
DEFAULT_ADMIN_USERNAME = os.getenv("ANTI_FRAUD_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("ANTI_FRAUD_ADMIN_PASSWORD", "Admin@123456")
REVIEW_ADMIN_USERNAME = os.getenv("ANTI_FRAUD_REVIEW_ADMIN_USERNAME", "123456")
REVIEW_ADMIN_PASSWORD = os.getenv("ANTI_FRAUD_REVIEW_ADMIN_PASSWORD", "123456")
MAX_FAILED_LOGINS = int(os.getenv("ANTI_FRAUD_ADMIN_MAX_FAILED_LOGINS", "5") or 5)
LOCKOUT_MINUTES = int(os.getenv("ANTI_FRAUD_ADMIN_LOCKOUT_MINUTES", "15") or 15)


def _now() -> datetime:
    return datetime.utcnow()


def _now_text() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _hash_password(password: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 160000)
    return digest.hex()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _public_user(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "user_id": doc.get("user_id", ""),
        "username": doc.get("username", ""),
        "display_name": doc.get("display_name", doc.get("username", "")),
        "roles": doc.get("roles", []),
        "enabled": doc.get("enabled", True),
    }


def _password_matches(doc: Dict[str, Any], password: str) -> bool:
    salt = str(doc.get("password_salt") or "")
    expected = str(doc.get("password_hash") or "")
    if not salt or not expected:
        return False
    return hmac.compare_digest(expected, _hash_password(password, salt))


def ensure_review_admin() -> None:
    if not REVIEW_ADMIN_USERNAME or not REVIEW_ADMIN_PASSWORD:
        return
    if is_weak_password(REVIEW_ADMIN_PASSWORD) and not env_bool("ANTI_FRAUD_ALLOW_INSECURE_DEFAULTS", False):
        return
    tool = get_business_mongo_tool()
    doc = tool.db["admin_users"].find_one({"username": REVIEW_ADMIN_USERNAME}, {"_id": 0})
    roles = ["admin", "reviewer", "publisher", "report_reviewer"]
    if doc and doc.get("enabled", True) and set(roles).issubset(set(doc.get("roles") or [])) and _password_matches(doc, REVIEW_ADMIN_PASSWORD):
        return
    salt = secrets.token_hex(16)
    now = _now_text()
    payload = {
        "user_id": (doc or {}).get("user_id") or f"admin_review_{REVIEW_ADMIN_USERNAME}",
        "username": REVIEW_ADMIN_USERNAME,
        "display_name": (doc or {}).get("display_name") or "审核管理员",
        "roles": roles,
        "password_salt": salt,
        "password_hash": _hash_password(REVIEW_ADMIN_PASSWORD, salt),
        "enabled": True,
        "must_change_password": False,
        "updated_at": now,
    }
    if doc:
        tool.db["admin_users"].update_one({"username": REVIEW_ADMIN_USERNAME}, {"$set": payload})
        write_audit_log("admin_review_user_reset", {"username": REVIEW_ADMIN_USERNAME})
    else:
        payload["created_at"] = now
        tool.db["admin_users"].insert_one(payload)
        write_audit_log("admin_review_user_bootstrap", {"username": REVIEW_ADMIN_USERNAME})


def ensure_default_admin() -> None:
    tool = get_business_mongo_tool()
    if tool.db["admin_users"].count_documents({}) > 0:
        ensure_review_admin()
        return
    if is_weak_password(DEFAULT_ADMIN_PASSWORD) and not env_bool("ANTI_FRAUD_ALLOW_INSECURE_DEFAULTS", False):
        raise RuntimeError(
            "Refusing to bootstrap a weak default admin password. Set a strong "
            "ANTI_FRAUD_ADMIN_PASSWORD (10+ characters), or explicitly enable "
            "ANTI_FRAUD_ALLOW_INSECURE_DEFAULTS=1 for a disposable local demo."
        )
    salt = secrets.token_hex(16)
    user = {
        "user_id": "admin_default",
        "username": DEFAULT_ADMIN_USERNAME,
        "display_name": "系统管理员",
        "roles": ["admin", "reviewer", "publisher"],
        "password_salt": salt,
        "password_hash": _hash_password(DEFAULT_ADMIN_PASSWORD, salt),
        "enabled": True,
        "must_change_password": DEFAULT_ADMIN_PASSWORD == "Admin@123456",
        "created_at": _now_text(),
        "updated_at": _now_text(),
    }
    tool.db["admin_users"].insert_one(user)
    write_audit_log("admin_user_bootstrap", {"username": DEFAULT_ADMIN_USERNAME})
    ensure_review_admin()


def authenticate_admin(username: str, password: str, ip: str = "") -> Dict[str, Any]:
    ensure_default_admin()
    tool = get_business_mongo_tool()
    doc = tool.db["admin_users"].find_one({"username": username}, {"_id": 0})
    if not doc or not doc.get("enabled", True):
        write_audit_log("admin_login_failed", {"username": username, "ip": ip, "reason": "user_not_found"})
        raise HTTPException(status_code=401, detail="账号或密码错误")
    locked_until = doc.get("locked_until")
    if isinstance(locked_until, datetime) and locked_until > _now():
        write_audit_log("admin_login_blocked", {"username": username, "ip": ip, "reason": "temporary_lockout"})
        raise HTTPException(status_code=429, detail="登录失败次数过多，请稍后再试")
    salt = str(doc.get("password_salt") or "")
    expected = str(doc.get("password_hash") or "")
    actual = _hash_password(password, salt)
    if not hmac.compare_digest(expected, actual):
        failed_count = int(doc.get("failed_login_count", 0) or 0) + 1
        update: Dict[str, Any] = {"failed_login_count": failed_count, "last_failed_login_at": _now_text()}
        if failed_count >= MAX_FAILED_LOGINS:
            update["locked_until"] = _now() + timedelta(minutes=LOCKOUT_MINUTES)
        tool.db["admin_users"].update_one(
            {"username": username},
            {"$set": update},
        )
        write_audit_log("admin_login_failed", {"username": username, "ip": ip, "reason": "bad_password"})
        raise HTTPException(status_code=401, detail="账号或密码错误")
    tool.db["admin_users"].update_one(
        {"username": username},
        {
            "$set": {"last_login_at": _now_text(), "updated_at": _now_text()},
            "$unset": {"failed_login_count": "", "locked_until": ""},
        },
    )
    write_audit_log("admin_login_success", {"username": username, "ip": ip})
    return _public_user(doc)


def create_admin_session(user: Dict[str, Any], ip: str = "", user_agent: str = "") -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    token = secrets.token_urlsafe(36)
    expires = _now() + timedelta(hours=SESSION_HOURS)
    session = {
        "session_id": secrets.token_hex(12),
        "token_hash": _hash_token(token),
        "user_id": user.get("user_id", ""),
        "username": user.get("username", ""),
        "roles": user.get("roles", []),
        "ip": ip,
        "user_agent": user_agent[:300],
        "created_at": _now_text(),
        "last_seen_at": _now_text(),
        "expires_at": expires.isoformat(timespec="seconds"),
        "expires_at_ts": expires,
    }
    tool.db["admin_sessions"].insert_one(session)
    return {"token": token, "expires_at": session["expires_at"], "user": user}


def get_admin_from_token(token: str) -> Dict[str, Any]:
    if not token:
        raise HTTPException(status_code=401, detail="未登录")
    tool = get_business_mongo_tool()
    session = tool.db["admin_sessions"].find_one({"token_hash": _hash_token(token)}, {"_id": 0})
    if not session:
        raise HTTPException(status_code=401, detail="登录已失效")
    expires = session.get("expires_at_ts")
    if isinstance(expires, datetime) and expires < _now():
        tool.db["admin_sessions"].delete_one({"token_hash": _hash_token(token)})
        raise HTTPException(status_code=401, detail="登录已过期")
    user = tool.db["admin_users"].find_one({"user_id": session.get("user_id")}, {"_id": 0})
    if not user or not user.get("enabled", True):
        raise HTTPException(status_code=401, detail="账号不可用")
    tool.db["admin_sessions"].update_one(
        {"token_hash": _hash_token(token)},
        {"$set": {"last_seen_at": _now_text()}},
    )
    return _public_user(user)


def require_admin_user(request: Request) -> Dict[str, Any]:
    token = request.cookies.get(SESSION_COOKIE, "")
    user = get_admin_from_token(token)
    roles = set(user.get("roles") or [])
    if "admin" not in roles:
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


def destroy_admin_session(token: str) -> None:
    if not token:
        return
    tool = get_business_mongo_tool()
    tool.db["admin_sessions"].delete_one({"token_hash": _hash_token(token)})
