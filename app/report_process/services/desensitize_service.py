import re


def desensitize_text(text: str) -> str:
    value = str(text or "")
    value = re.sub(r"(?<!\d)(1[3-9]\d)\d{4}(\d{4})(?!\d)", r"\1****\2", value)
    value = re.sub(r"(?<!\d)(\d{6})\d{8}(\d{3}[\dXx])(?!\d)", r"\1********\2", value)
    value = re.sub(r"(?<!\d)(\d{6})\d{6,9}(\d{4})(?!\d)", r"\1********\2", value)
    value = re.sub(r"(验证码|校验码|动态码)\s*[:：]?\s*\d{4,8}", r"\1：******", value)
    value = re.sub(r"(短信|收到|发送|提供)\s*(\d{4,8})", r"\1******", value)
    return value
