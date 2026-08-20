import asyncio
from pathlib import Path

from fastapi import HTTPException
from langchain_core.messages import HumanMessage
import pytest

from app.core.security import LOCAL_CORS_ORIGINS, cors_origins, is_weak_password
from app.lm.lm_utils import PrivacyAwareLLMClient
from app.modules.knowledge_assistant.emotion import classify_text_emotion, with_emotion_context
from app.query_process.agent.memory.memory_redactor import redact_sensitive_text, sanitize_external_payload


class _RecordingClient:
    def __init__(self):
        self.value = None

    def invoke(self, value, *args, **kwargs):
        self.value = value
        return value

    def stream(self, value, *args, **kwargs):
        self.value = value
        return iter([value])


def test_default_cors_is_explicit_and_local(monkeypatch):
    monkeypatch.delenv("ANTI_FRAUD_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("ANTI_FRAUD_ALLOW_INSECURE_CORS", raising=False)
    assert cors_origins() == LOCAL_CORS_ORIGINS
    assert "*" not in cors_origins()


def test_import_service_uses_shared_security_baseline():
    source = (
        Path(__file__).parents[1] / "app/import_process/api/file_import_service.py"
    ).read_text(encoding="utf-8")
    assert "app.add_middleware(SecurityMiddleware)" in source
    assert "allow_origins=cors_origins()" in source
    assert 'allow_origins=["*"]' not in source
    assert 'allow_methods=["*"]' not in source
    assert 'allow_headers=["*"]' not in source


def test_local_compose_does_not_publish_data_nodes_on_all_interfaces():
    compose = (Path(__file__).parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
    for mapping in (
        "127.0.0.1:19530:19530",
        "127.0.0.1:9091:9091",
        "127.0.0.1:27017:27017",
        "127.0.0.1:10096:10095",
    ):
        assert mapping in compose


def test_wildcard_cors_requires_explicit_insecure_override(monkeypatch):
    monkeypatch.setenv("ANTI_FRAUD_CORS_ORIGINS", "*")
    monkeypatch.delenv("ANTI_FRAUD_ALLOW_INSECURE_CORS", raising=False)
    try:
        cors_origins()
    except RuntimeError as exc:
        assert "Wildcard CORS is disabled" in str(exc)
    else:
        raise AssertionError("wildcard CORS must be rejected by default")


def test_weak_admin_password_detection():
    assert is_weak_password("123456")
    assert is_weak_password("Admin@123456")
    assert not is_weak_password("S3cure-Unique-Password-2026")


def test_sensitive_text_redaction_masks_credentials_but_keeps_amount():
    text = "手机号13800138000，身份证11010519491231002X，银行卡6222021234567890123，验证码123456，转账500元"
    redacted = redact_sensitive_text(text)
    assert "13800138000" not in redacted
    assert "11010519491231002X" not in redacted
    assert "6222021234567890123" not in redacted
    assert "验证码123456" not in redacted
    assert "500元" in redacted


def test_external_llm_proxy_redacts_nested_message_content():
    raw = _RecordingClient()
    client = PrivacyAwareLLMClient(raw)
    client.invoke([HumanMessage(content="我的银行卡6222021234567890123，验证码：123456")])
    content = raw.value[0].content
    assert "6222021234567890123" not in content
    assert "123456" not in content
    nested = sanitize_external_payload({"history": ["电话13800138000"]})
    assert "13800138000" not in nested["history"][0]


def test_text_input_gets_an_emotion_label_and_safe_context():
    emotion = classify_text_emotion("怎么办，我刚刚转账了！")
    assert emotion["key"] == "panic"
    assert emotion["label"] == "惊慌"
    enriched, metadata = with_emotion_context("我担心这个链接是不是假的", "text")
    assert metadata["source"] == "text_input"
    assert metadata["label"] == "焦虑"
    assert "内部情绪提示" in enriched
    assert "建议回应基调" in enriched


def test_session_deletion_requires_admin(monkeypatch):
    from app.query_process.api import app as query_app

    deleted = []

    def deny(_request):
        raise HTTPException(status_code=401, detail="未登录")

    monkeypatch.setattr(query_app, "require_admin_user", deny)
    monkeypatch.setattr(query_app, "clear_history", lambda session_id: deleted.append(session_id))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(query_app.delete_workspace_session("knowledge", "session-1", object()))
    assert exc_info.value.status_code == 401
    assert deleted == []


def test_history_deletion_requires_admin(monkeypatch):
    from app.modules.emergency_dissuasion import api as emergency_api

    deleted = []

    def deny(_request):
        raise HTTPException(status_code=401, detail="未登录")

    monkeypatch.setattr(emergency_api, "require_admin_user", deny)
    monkeypatch.setattr(emergency_api, "clear_history", lambda session_id: deleted.append(session_id))

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(emergency_api.clear_chat_history("session-1", object()))
    assert exc_info.value.status_code == 401
    assert deleted == []


def test_frontend_does_not_persist_plaintext_credentials():
    page = Path(__file__).parents[1] / "app/query_process/page/chat.html"
    source = page.read_text(encoding="utf-8")
    assert "users[account] = { password" not in source
    assert "credentialDigest" in source
    assert "localStorage.removeItem(LEGACY_AUTH_USERS_KEY)" in source
    assert "deriveCredentialDigest(password, salt)" in source


def test_frontend_text_messages_include_emotion_metadata():
    page = Path(__file__).parents[1] / "app/query_process/page/chat.html"
    source = page.read_text(encoding="utf-8")
    assert 'analyzeEmotion(text, inputMode)' in source
    assert 'signal.textContent = "情绪：" + label' in source
    assert '"语音情绪"' not in source
    assert '"文字情绪"' not in source
    assert "emotion: options.emotion || null" in source
