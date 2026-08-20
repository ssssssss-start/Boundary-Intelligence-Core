from __future__ import annotations

import re


_DIGITS = "零一二三四五六七八九"
_SMALL_UNITS = ["", "十", "百", "千"]
_BIG_UNITS = ["", "万", "亿", "兆"]
_FULLWIDTH_DIGITS = str.maketrans(
    {
        "０": "0",
        "１": "1",
        "２": "2",
        "３": "3",
        "４": "4",
        "５": "5",
        "６": "6",
        "７": "7",
        "８": "8",
        "９": "9",
        "．": ".",
        "％": "%",
    }
)

_CODE_LABELS = (
    "验证码",
    "校验码",
    "动态码",
    "短信码",
    "尾号",
    "编号",
    "工号",
    "订单号",
    "单号",
    "账号",
    "账户",
    "卡号",
    "银行卡号",
    "手机号",
    "手机号码",
    "电话",
    "联系方式",
    "身份证",
)


def _digits_to_spoken(value: str) -> str:
    return "".join(_DIGITS[int(ch)] for ch in value if ch.isdigit())


def _four_digits_to_chinese(value: str, omit_leading_one_for_ten: bool) -> str:
    value = value.lstrip("0") or "0"
    if value == "0":
        return _DIGITS[0]

    result: list[str] = []
    zero_pending = False
    length = len(value)
    for index, char in enumerate(value):
        digit = int(char)
        unit = _SMALL_UNITS[length - index - 1]
        if digit == 0:
            zero_pending = bool(result)
            continue
        if zero_pending and result and result[-1] != _DIGITS[0]:
            result.append(_DIGITS[0])
        if not (
            digit == 1
            and unit == "十"
            and not result
            and omit_leading_one_for_ten
        ):
            result.append(_DIGITS[digit])
        result.append(unit)
        zero_pending = False
    return "".join(result)


def integer_to_chinese(value: str) -> str:
    value = re.sub(r"\D", "", value or "")
    if not value:
        return ""
    if len(value) > 1 and value.startswith("0"):
        return _digits_to_spoken(value)
    if len(value) >= 7:
        return _digits_to_spoken(value)

    value = value.lstrip("0") or "0"
    if value == "0":
        return _DIGITS[0]

    chunks: list[str] = []
    cursor = len(value)
    while cursor > 0:
        start = max(0, cursor - 4)
        chunks.insert(0, value[start:cursor])
        cursor = start

    result: list[str] = []
    zero_pending = False
    total = len(chunks)
    for index, chunk in enumerate(chunks):
        chunk_int = int(chunk)
        big_unit = _BIG_UNITS[total - index - 1]
        if chunk_int == 0:
            zero_pending = bool(result)
            continue
        if result and (zero_pending or (len(chunk) == 4 and chunk_int < 1000)):
            if result[-1] != _DIGITS[0]:
                result.append(_DIGITS[0])
        result.append(_four_digits_to_chinese(chunk, omit_leading_one_for_ten=index == 0))
        result.append(big_unit)
        zero_pending = False
    return "".join(result)


def number_to_chinese(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    sign = ""
    if value[0] in "+-":
        sign = "加" if value[0] == "+" else "负"
        value = value[1:]
    value = value.replace(",", "")
    if "." in value:
        integer, decimal = value.split(".", 1)
        decimal_text = _digits_to_spoken(decimal)
        return f"{sign}{integer_to_chinese(integer or '0')}点{decimal_text}"
    return f"{sign}{integer_to_chinese(value)}"


def _count_to_chinese(value: str) -> str:
    return integer_to_chinese(str(int(value or "0")))


def normalize_numbers_for_chinese_tts(text: str) -> str:
    normalized = str(text or "").translate(_FULLWIDTH_DIGITS)
    normalized = re.sub(r"(?<=\d),(?=\d)", "", normalized)

    code_labels = "|".join(re.escape(label) for label in _CODE_LABELS)
    normalized = re.sub(
        rf"({code_labels})([：:\s]*)(\d{{4,}})",
        lambda match: f"{match.group(1)}{match.group(2)}{_digits_to_spoken(match.group(3))}",
        normalized,
    )
    normalized = re.sub(
        r"(?<!\d)(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?!\d)",
        lambda match: (
            f"{_digits_to_spoken(match.group(1))}年"
            f"{_count_to_chinese(match.group(2))}月"
            f"{_count_to_chinese(match.group(3))}日"
        ),
        normalized,
    )
    normalized = re.sub(
        r"(?<!\d)(\d{4})年(\d{1,2})月(\d{1,2})日?",
        lambda match: (
            f"{_digits_to_spoken(match.group(1))}年"
            f"{_count_to_chinese(match.group(2))}月"
            f"{_count_to_chinese(match.group(3))}日"
        ),
        normalized,
    )
    normalized = re.sub(
        r"(?<!\d)(\d{1,2}):(\d{2})(?!\d)",
        lambda match: (
            f"{_count_to_chinese(match.group(1))}点"
            f"{_digits_to_spoken(match.group(2)) if match.group(2).startswith('0') else integer_to_chinese(match.group(2))}分"
        ),
        normalized,
    )
    normalized = re.sub(
        r"[¥￥]\s*(\d+(?:\.\d+)?)(?!\s*[-~—–])",
        lambda match: f"{number_to_chinese(match.group(1))}元",
        normalized,
    )
    normalized = re.sub(r"[¥￥]", "人民币", normalized)
    normalized = re.sub(
        r"(\d+(?:\.\d+)?)\s*[-~—–]\s*(\d+(?:\.\d+)?)",
        lambda match: f"{number_to_chinese(match.group(1))}到{number_to_chinese(match.group(2))}",
        normalized,
    )
    normalized = re.sub(
        r"(\d+(?:\.\d+)?)\s*%",
        lambda match: f"百分之{number_to_chinese(match.group(1))}",
        normalized,
    )
    normalized = re.sub(
        r"(?<![A-Za-z0-9_])\+(\d+(?:\.\d+)?)",
        lambda match: f"加{number_to_chinese(match.group(1))}",
        normalized,
    )
    normalized = re.sub(
        r"(?<![A-Za-z0-9_])-(?!\s)(\d+(?:\.\d+)?)",
        lambda match: f"负{number_to_chinese(match.group(1))}",
        normalized,
    )
    normalized = re.sub(
        r"\d+\.\d+",
        lambda match: number_to_chinese(match.group(0)),
        normalized,
    )
    normalized = re.sub(
        r"\d+",
        lambda match: integer_to_chinese(match.group(0)),
        normalized,
    )
    return normalized
