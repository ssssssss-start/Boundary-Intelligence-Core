from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from app.modules.suspicious_report.report_intel import (
    advice_for_scam_ids,
    display_empty_text,
    evidence_requirements_for_scam_ids,
    report_domain_allowlist,
    report_domain_watchlist,
    report_risk_phrases,
    report_rule_combos,
    report_scam_type_aliases,
    report_scam_type_names,
    report_url_rules,
)
from app.query_process.services.scam_rule_engine import risk_level_from_score


URL_CHARS = r"A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-"
URL_PATTERN = re.compile(rf"(?i)\b(?:https?://|www\.)[{URL_CHARS}]+")
BARE_URL_PATTERN = re.compile(
    rf"(?i)(?<![@\w.-])"
    rf"(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+"
    rf"(?:com|cn|net|org|top|xyz|vip|click|shop|icu|cc|edu|gov|io|app|info|me|co|site|online|store|ink|live|pro|club|wang)"
    rf"(?::\d{{2,5}})?(?:[/?#][{URL_CHARS}]*)?"
)

GENERIC_LINK_KEYWORDS = {"http", "https", "链接", "网址", "二维码"}
GENERIC_SENSITIVE_KEYWORDS = {
    "验证码",
    "短信码",
    "动态码",
    "登录码",
    "支付码",
    "银行卡",
    "身份证",
    "支付密码",
    "密码",
    "人脸识别",
    "实名信息",
    "账号密码",
}
CONTEXT_EVIDENCE_TOKENS = {
    "中奖",
    "领奖",
    "客服",
    "售后",
    "快递",
    "退款",
    "理赔",
    "奖助学金",
    "助学金",
    "补贴",
    "退票",
    "退改签",
    "航班",
    "火车票",
    "征信",
    "贷款",
    "投资",
    "刷单",
    "屏幕共享",
    "会议软件",
    "安全账户",
    "涉案",
}
GENERIC_FRAUD_FEATURES = {"点击陌生链接", "索要验证码", "索要银行卡或身份信息", "仿冒异常域名"}
LINK_OR_ACCOUNT_FRAUD_TYPES = {"钓鱼链接诈骗", "验证码/账户盗刷诈骗"}
CORE_LINK_OR_ACCOUNT_SCAM_IDS = {"scam_phishing_link", "scam_code_account_theft"}


def _scam_type_names() -> Dict[str, str]:
    return report_scam_type_names()


def _scam_type_aliases() -> Dict[str, List[str]]:
    return report_scam_type_aliases()


def _scam_name(scam_id: str) -> str:
    return _scam_type_names().get(str(scam_id or ""), "")


def _knowledge_features() -> List[Dict[str, Any]]:
    return report_risk_phrases()


def _knowledge_rules() -> List[Dict[str, Any]]:
    return report_rule_combos()


def extract_urls(content: str) -> List[str]:
    urls: List[str] = []
    spans: List[tuple[int, int]] = []
    for match in URL_PATTERN.finditer(content or ""):
        url = match.group(0).strip().rstrip(".,;，。；")
        if url and url not in urls:
            urls.append(url)
            spans.append(match.span())
    for match in BARE_URL_PATTERN.finditer(content or ""):
        if any(start <= match.start() < end for start, end in spans):
            continue
        url = match.group(0).strip().rstrip(".,;，。；")
        if url and url not in urls:
            urls.append(url)
    return urls


def _parse_url(raw_url: str):
    value = (raw_url or "").strip()
    parse_target = value if re.match(r"(?i)^https?://", value) else f"http://{value}"
    return urlparse(parse_target)


def _safe_url(raw_url: str) -> str:
    parsed = _parse_url(raw_url)
    scheme = parsed.scheme or "http"
    host = parsed.netloc.lower()
    path = parsed.path or ""
    if not host:
        return raw_url
    suffix = "?..." if parsed.query else ""
    return f"{scheme}://{host}{path}{suffix}"


def sanitize_urls(urls: List[str]) -> List[str]:
    return [_safe_url(url) for url in urls]


def sanitize_content_urls(content: str) -> str:
    value = str(content or "")
    for raw_url in extract_urls(value):
        value = value.replace(raw_url, _safe_url(raw_url))
    return value


def _host_matches_domain(host: str, domain: str, scope: str = "exact_or_subdomain") -> bool:
    host = (host or "").lower().strip(".")
    domain = (domain or "").lower().strip(".")
    if not host or not domain:
        return False
    if scope == "suffix":
        return host == domain or host.endswith(f".{domain}")
    return host == domain or host.endswith(f".{domain}")


def _allowlist_entry_for_host(host: str) -> Dict[str, Any]:
    for item in report_domain_allowlist():
        if _host_matches_domain(host, str(item.get("domain") or ""), str(item.get("scope") or "exact_or_subdomain")):
            return item
    return {}


def _watchlist_items(key: str) -> List[str]:
    value = report_domain_watchlist().get(key) or []
    return [str(item).lower() for item in value if item]


def _url_host(raw_url: str) -> str:
    return (_parse_url(raw_url).netloc or "").lower().strip(".")


def _raw_has_http_scheme(raw_url: str) -> bool:
    return bool(re.match(r"(?i)^http://", str(raw_url or "").strip()))


def _url_rule_matches(rule: Dict[str, Any], raw_url: str, content: str) -> bool:
    parsed = _parse_url(raw_url)
    host = (parsed.netloc or "").lower()
    path_query = f"{parsed.path or ''}?{parsed.query or ''}".lower()
    url_text = f"{host}{path_query}"
    matcher = str(rule.get("matcher") or "")
    params = rule.get("params") or {}

    if matcher == "raw_http_scheme":
        return _raw_has_http_scheme(raw_url)
    if matcher == "short_link_host":
        hosts = [str(item).lower() for item in params.get("hosts") or _watchlist_items("short_link_hosts")]
        return any(_host_matches_domain(host, item) for item in hosts)
    if matcher == "sensitive_path_token":
        tokens = [str(item).lower() for item in params.get("tokens") or _watchlist_items("sensitive_path_tokens")]
        return any(token and token in path_query for token in tokens)
    if matcher == "risky_suffix":
        suffixes = [str(item).lower() for item in params.get("suffixes") or _watchlist_items("risky_suffixes")]
        return any(host.endswith(suffix) for suffix in suffixes)
    if matcher == "random_domain_segment":
        return bool(re.search(r"(?:^|[.-])[a-z0-9]{14,}(?:[.-]|$)", host))
    if matcher == "ip_host":
        return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
    if matcher == "deep_subdomain":
        return host.count(".") >= int(params.get("min_dot_count", 4) or 4)
    if matcher == "punycode_host":
        return "xn--" in host
    if matcher == "brand_impersonation":
        if _allowlist_entry_for_host(host):
            return False
        brand_tokens = [str(item).lower() for item in _watchlist_items("brand_tokens")]
        return any(token and token in host for token in brand_tokens)
    if matcher == "redirect_parameter":
        tokens = [str(item).lower() for item in params.get("tokens") or []]
        return any(token and token in path_query for token in tokens)
    if matcher == "app_download_hint":
        tokens = [str(item).lower() for item in params.get("tokens") or _watchlist_items("app_download_tokens")]
        merged = f"{url_text} {(content or '').lower()}"
        return any(token and token.lower() in merged for token in tokens)
    return False


def _add_rule(
    rules: List[Dict[str, Any]],
    rule_id: str,
    label: str,
    score: int,
    evidence: str = "",
    scam_id: str = "scam_phishing_link",
    feature_name: str = "",
    source: str = "report_intel:url_rules",
) -> None:
    if any(item.get("rule_id") == rule_id and item.get("evidence") == evidence for item in rules):
        return
    rules.append(
        {
            "rule_id": rule_id,
            "label": label,
            "score": int(score),
            "evidence": evidence,
            "scam_id": scam_id,
            "scam_type": _scam_name(scam_id) or "钓鱼链接诈骗",
            "feature_name": feature_name or label,
            "source": source,
        }
    )


def analyze_url_features(content: str) -> Dict[str, Any]:
    urls = extract_urls(content)
    rules: List[Dict[str, Any]] = []
    knowledge_features: List[str] = ["陌生链接诱导"] if urls else []
    allowlist_hits: List[Dict[str, Any]] = []

    for raw_url in urls:
        host = _url_host(raw_url)
        allowlist_entry = _allowlist_entry_for_host(host)
        if allowlist_entry:
            allowlist_hits.append(
                {
                    "domain": host,
                    "label": str(allowlist_entry.get("label") or "常见可信域名"),
                    "risk_adjustment": int(allowlist_entry.get("risk_adjustment", 0) or 0),
                }
            )

        for rule in report_url_rules():
            if allowlist_entry and str(rule.get("matcher") or "") in {"raw_http_scheme", "risky_suffix", "deep_subdomain", "brand_impersonation"}:
                continue
            if not _url_rule_matches(rule, raw_url, content):
                continue
            _add_rule(
                rules,
                str(rule.get("rule_id") or ""),
                str(rule.get("label") or ""),
                int(rule.get("score", 0) or 0),
                _safe_url(raw_url),
                scam_id=str(rule.get("scam_id") or "scam_phishing_link"),
                feature_name=str(rule.get("feature_name") or ""),
                source="report_intel:url_rules",
            )

    for item in rules:
        feature_name = str(item.get("feature_name") or "").strip()
        if feature_name and feature_name not in knowledge_features:
            knowledge_features.append(feature_name)

    score = min(100, sum(int(item.get("score", 0)) for item in rules))
    return {
        "urls": sanitize_urls(urls),
        "risk_score": score,
        "risk_level": risk_level_from_score(score),
        "rule_hits": rules,
        "matched_rules": [item["label"] for item in rules],
        "allowlist_hits": allowlist_hits,
        "knowledge_features": list(dict.fromkeys(knowledge_features)),
        "report_features": list(dict.fromkeys(knowledge_features)),
        "empty_text": display_empty_text("url_features" if urls else "url_features_no_url", "暂无明显链接特征命中。"),
    }


def _keyword_hit(content: str, keyword: str) -> bool:
    token = str(keyword or "").strip()
    if not token or token in GENERIC_LINK_KEYWORDS:
        return False
    return token.lower() in (content or "").lower()


def _regex_hits(content: str, patterns: List[str]) -> List[str]:
    hits: List[str] = []
    for pattern in patterns or []:
        if not pattern:
            continue
        try:
            if re.search(pattern, content or "", flags=re.IGNORECASE):
                hits.append(f"正则:{pattern}")
        except re.error:
            continue
    return hits


def _has_non_generic_evidence(matched: List[str]) -> bool:
    for item in matched:
        if item.startswith("正则:"):
            if any(token in item for token in CONTEXT_EVIDENCE_TOKENS):
                return True
            continue
        evidence = item.strip()
        if evidence and evidence not in GENERIC_LINK_KEYWORDS and evidence not in GENERIC_SENSITIVE_KEYWORDS:
            return True
    return False


def _has_request_context(text: str) -> bool:
    return bool(re.search(r"(对方|客服|老师|平台|系统|警官|卖家|买家|他|她|他们).{0,12}(让我|叫我|要求|要我|发给|提供|填写|输入|转账|充值|下载|共享)", text or ""))


def _looks_like_prevention_statement(text: str) -> bool:
    compact = re.sub(r"\s+", "", text or "")
    if not compact:
        return False
    prevention = any(token in compact for token in ["反诈科普", "科普：", "安全提醒", "不要告诉任何人", "不能告诉任何人", "不要随便点链接"])
    dangerous_request = bool(re.search(r"(对方|客服|老师|平台|警官|卖家|买家|他|她|他们).{0,18}(让我|叫我|要求|要我|发给|提供|填写|输入|转账|充值|下载|共享)", compact))
    return prevention and not dangerous_request


def _active_scam_ids_from_text(text: str, candidates: List[Dict[str, Any]]) -> set[str]:
    lowered = (text or "").lower()
    active: set[str] = set()
    for scam_id, aliases in _scam_type_aliases().items():
        if any(alias and alias.lower() in lowered for alias in aliases):
            active.add(scam_id)
    for item in candidates:
        scam_id = str(item.get("scam_id") or "")
        feature = item.get("feature") or {}
        strength = str(feature.get("evidence_strength") or "")
        if scam_id and strength == "core":
            active.add(scam_id)
            continue
        if scam_id and scam_id in active and (
            _has_non_generic_evidence(item.get("matched") or [])
            or _has_request_context(text)
        ):
            active.add(scam_id)
    return active


def analyze_keyword_blacklist(content: str) -> Dict[str, Any]:
    text = content or ""
    if _looks_like_prevention_statement(text):
        return {
            "risk_score": 0,
            "risk_level": risk_level_from_score(0),
            "rule_hits": [],
            "matched_rules": [],
            "empty_text": display_empty_text("keyword_hits", "暂未发现明显高危话术。"),
        }
    candidates: List[Dict[str, Any]] = []
    for feature in _knowledge_features():
        feature_name = str(feature.get("feature_name") or "").strip()
        if not feature_name:
            continue
        matched = [str(kw) for kw in feature.get("keywords") or [] if _keyword_hit(text, str(kw))]
        patterns = [] if feature_name == "点击陌生链接" else [str(item) for item in feature.get("regex_patterns") or [] if item]
        matched.extend(_regex_hits(text, patterns))
        if matched:
            candidates.append(
                {
                    "feature": feature,
                    "feature_name": feature_name,
                    "matched": matched,
                    "scam_id": str(feature.get("scam_id") or ""),
                }
            )

    active_scam_ids = _active_scam_ids_from_text(text, candidates)
    rules: List[Dict[str, Any]] = []
    for candidate in candidates:
        feature = candidate["feature"]
        feature_name = candidate["feature_name"]
        matched = candidate["matched"]
        scam_id = candidate["scam_id"]
        if scam_id not in active_scam_ids and scam_id not in CORE_LINK_OR_ACCOUNT_SCAM_IDS:
            continue
        scam_type = _scam_name(scam_id)
        display_label = str(feature.get("display_label") or feature_name)
        rules.append(
            {
                "rule_id": str(feature.get("feature_id") or feature_name),
                "label": f"高危话术：{display_label}",
                "score": int(feature.get("risk_weight", 0) or 0),
                "evidence": "、".join(matched[:5]),
                "scam_id": scam_id,
                "scam_type": scam_type,
                "feature_name": feature_name,
                "display_label": display_label,
                "stage": str(feature.get("stage") or ""),
                "explanation": str(feature.get("explanation") or ""),
                "source": "report_intel:risk_phrases",
                "advice_tags": feature.get("advice_tags") or [],
            }
        )

    score = min(100, sum(int(item.get("score", 0)) for item in rules))
    return {
        "risk_score": score,
        "risk_level": risk_level_from_score(score),
        "rule_hits": rules,
        "matched_rules": [item["label"] for item in rules],
        "empty_text": display_empty_text("keyword_hits", "暂未发现明显高危话术。"),
    }


def _feature_names(url_result: Dict[str, Any], keyword_result: Dict[str, Any]) -> set[str]:
    names = set(str(item) for item in url_result.get("knowledge_features") or [] if item)
    for item in keyword_result.get("rule_hits") or []:
        feature_name = str(item.get("feature_name") or "").strip()
        if feature_name:
            names.add(feature_name)
    return names


def evaluate_knowledge_rule_matches(url_result: Dict[str, Any], keyword_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    names = _feature_names(url_result, keyword_result)
    if not names:
        return []

    matches: List[Dict[str, Any]] = []
    for rule in _knowledge_rules():
        conditions = rule.get("conditions") or {}
        all_items = [str(item) for item in conditions.get("all") or [] if item]
        any_items = [str(item) for item in conditions.get("any") or [] if item]
        min_any = int(conditions.get("min_any", 0) or 0)
        if all_items and not all(item in names for item in all_items):
            continue
        any_hit = [item for item in any_items if item in names]
        if min_any and len(any_hit) < min_any:
            continue
        if not all_items and not any_hit:
            continue
        scam_id = str(rule.get("scam_id") or "")
        fraud_type = _scam_name(scam_id) or str(rule.get("fraud_type") or "")
        matched_conditions = set(all_items + any_hit)
        if fraud_type not in LINK_OR_ACCOUNT_FRAUD_TYPES and matched_conditions and matched_conditions.issubset(GENERIC_FRAUD_FEATURES):
            continue
        matches.append(
            {
                "rule_id": str(rule.get("rule_id") or ""),
                "label": f"组合研判：{rule.get('name') or fraud_type}",
                "score": int(rule.get("risk_score", 0) or 0),
                "evidence": str(rule.get("evidence_template") or rule.get("explanation") or "、".join(all_items + any_hit)),
                "scam_id": scam_id,
                "scam_type": fraud_type,
                "fraud_type": fraud_type,
                "risk_level": str(rule.get("risk_level") or risk_level_from_score(int(rule.get("risk_score", 0) or 0))),
                "conditions_all": all_items,
                "conditions_any_hit": any_hit,
                "source": "report_intel:rule_combos",
                "advice_tags": rule.get("advice_tags") or [],
            }
        )
    return matches


def score_suspicious_item(url_result: Dict[str, Any], keyword_result: Dict[str, Any]) -> Dict[str, Any]:
    url_score = int(url_result.get("risk_score", 0) or 0)
    keyword_score = int(keyword_result.get("risk_score", 0) or 0)
    rule_matches = evaluate_knowledge_rule_matches(url_result, keyword_result)
    feature_names = _feature_names(url_result, keyword_result)
    bonus = 0
    if "中奖免费礼品诱导" in feature_names and any("验证码" in item for item in feature_names):
        bonus += 20
    if url_score and any(any(token in item for token in ["验证码", "银行卡", "身份", "密码"]) for item in feature_names):
        bonus += 15
    if any("客服" in item for item in feature_names) and any(any(token in item for token in ["屏幕", "远程", "下载", "APP", "App"]) for item in feature_names):
        bonus += 15
    if any(any(token in item for token in ["公检法", "涉案", "安全账户"]) for item in feature_names) and any(
        any(token in item for token in ["垫付", "缴纳", "资金", "银行卡", "身份"]) for item in feature_names
    ):
        bonus += 15

    rule_score = max([int(item.get("score", 0) or 0) for item in rule_matches] or [0])
    score = max(min(100, url_score + keyword_score + bonus), rule_score)
    return {
        "risk_score": score,
        "risk_level": risk_level_from_score(score),
        "bonus_score": bonus,
        "knowledge_rule_hits": rule_matches,
        "knowledge_rule_score": rule_score,
    }


def classify_suspicious_type(url_result: Dict[str, Any], keyword_result: Dict[str, Any]) -> str:
    type_scores: Dict[str, int] = {}
    for item in evaluate_knowledge_rule_matches(url_result, keyword_result):
        scam_type = str(item.get("scam_type") or "")
        if scam_type:
            type_scores[scam_type] = type_scores.get(scam_type, 0) + int(item.get("score", 0) or 0)

    if int(url_result.get("risk_score", 0) or 0) > 0:
        type_scores["钓鱼链接诈骗"] = int(url_result.get("risk_score", 0) or 0)
    for item in keyword_result.get("rule_hits") or []:
        scam_type = str(item.get("scam_type") or "")
        feature_name = str(item.get("feature_name") or "")
        if feature_name in GENERIC_FRAUD_FEATURES and scam_type not in LINK_OR_ACCOUNT_FRAUD_TYPES:
            continue
        if scam_type:
            type_scores[scam_type] = type_scores.get(scam_type, 0) + int(item.get("score", 0) or 0)

    if not type_scores:
        return "暂未识出诈骗风险"
    ranked = sorted(type_scores.items(), key=lambda pair: pair[1], reverse=True)
    if ranked[0][1] < 30:
        return "暂未识出诈骗风险"
    threshold = max(60, int(ranked[0][1] * 0.7))
    selected = [name for name, score in ranked if score >= threshold][:3]
    return "、".join(selected) if selected else ranked[0][0]


def _hit_scam_ids(url_result: Dict[str, Any], keyword_result: Dict[str, Any]) -> List[str]:
    ids: List[str] = []
    for item in (url_result.get("rule_hits") or []) + (keyword_result.get("rule_hits") or []) + evaluate_knowledge_rule_matches(url_result, keyword_result):
        scam_id = str(item.get("scam_id") or "")
        if scam_id and scam_id not in ids:
            ids.append(scam_id)
    return ids


def _hit_advice_tags(url_result: Dict[str, Any], keyword_result: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    for item in (url_result.get("rule_hits") or []) + (keyword_result.get("rule_hits") or []) + evaluate_knowledge_rule_matches(url_result, keyword_result):
        for tag in item.get("advice_tags") or []:
            text = str(tag or "").strip()
            if text and text not in tags:
                tags.append(text)
    return tags


def _advice_from_tags(tags: List[str]) -> List[str]:
    mapping = {
        "stop_transfer": "不要继续转账、充值、垫付、补单或交保证金、解冻费。",
        "save_evidence": "保留聊天记录、链接、对方账号、收款信息和转账凭证，后续举报或报警会用到。",
        "bank_protect": "已经提供银行卡或发生转账的，尽快联系银行核查账户安全，必要时挂失或换卡。",
        "verify_official": "核实只走官方 App、官网或官方客服电话，不沿着对方给的电话、链接、二维码继续操作。",
        "protect_account": "不要提供验证码、短信码、支付码、密码、身份证、银行卡或人脸识别信息。",
        "stop_screen_share": "立即停止屏幕共享或远程控制，对方可能看到验证码和支付操作。",
        "stop_app_install": "不要安装对方发来的 App 或安装包，已经安装的先停止使用并排查权限。",
        "call_police": "如对方冒充公检法、要求转入安全账户或已经造成损失，及时拨打 110 或 96110 咨询。",
        "verify_identity": "涉及熟人、老师、领导借钱或代付时，先通过原号码、视频或当面核实身份。",
    }
    return [mapping[tag] for tag in tags if tag in mapping]


def build_report_advice(
    url_result: Dict[str, Any],
    keyword_result: Dict[str, Any],
    risk_score: int,
) -> List[str]:
    evidence_text = " ".join(
        str(item.get("label") or "") + " " + str(item.get("evidence") or "") + " " + str(item.get("feature_name") or "")
        for item in (url_result.get("rule_hits") or []) + (keyword_result.get("rule_hits") or [])
    )
    advice: List[str] = []
    scam_ids = _hit_scam_ids(url_result, keyword_result)

    if url_result.get("urls"):
        advice.append("不要点击可疑链接，不要在链接页面输入账号、密码、验证码、身份证或银行卡信息。")
    if "验证码" in evidence_text or "短信码" in evidence_text or "动态码" in evidence_text:
        advice.append("不要把验证码、短信码、动态码或支付码告诉任何人。")
    if any(token in evidence_text for token in ["银行卡", "身份证", "账号密码", "支付密码", "人脸识别"]):
        advice.append("不要提供银行卡、身份证、账号密码或人脸识别信息。")
    if any(token in evidence_text for token in ["屏幕共享", "远程控制", "远程协助"]):
        advice.append("立即停止屏幕共享或远程控制，对方能看到验证码和支付操作。")
    if any(token in evidence_text for token in ["下载App", "下载APP", "安装软件", "安装包", "陌生APP"]):
        advice.append("不要安装对方发来的 App 或安装包，已安装则先断网并卸载。")
    if any(token in evidence_text for token in ["保证金", "手续费", "解冻费", "垫付", "补单", "刷流水", "税费"]):
        advice.append("不要继续转账、垫付、补单、交保证金、手续费或解冻费。")
    advice.extend(_advice_from_tags(_hit_advice_tags(url_result, keyword_result)))
    advice.extend(advice_for_scam_ids(scam_ids)[:4])
    if risk_score >= 60:
        advice.append("保留短信、聊天记录、链接、对方账号和转账凭证，必要时拨打 96110 或 110。")
    else:
        advice.append("通过官方 App、官网或客服电话核实，不要使用对方提供的入口。")

    result: List[str] = []
    for item in advice:
        if item not in result:
            result.append(item)
    return result[:6]


def build_report_evidence(
    url_result: Dict[str, Any],
    keyword_result: Dict[str, Any],
    extra_scam_ids: List[str] | None = None,
) -> List[str]:
    items: List[str] = []
    scam_ids = _hit_scam_ids(url_result, keyword_result)
    for scam_id in extra_scam_ids or []:
        if scam_id and scam_id not in scam_ids:
            scam_ids.append(scam_id)
    for requirement in evidence_requirements_for_scam_ids(scam_ids):
        for value in (requirement.get("required_items") or []) + (requirement.get("urgent_actions") or []):
            text = str(value or "").strip()
            if text and text not in items:
                items.append(text)
    return items[:8]


def build_feedback_text(
    report_id: str,
    risk_level: str,
    risk_score: int,
    suspected_type: str,
    matched_rules: List[str],
    advice: List[str],
    status: str,
) -> str:
    status_text = "举报已提交并完成初步研判" if status == "submitted" else "已完成初步研判，举报记录暂未写入数据库"
    lines = [
        f"{status_text}：{report_id}",
        f"初步结论：{risk_level}，风险分 {risk_score}，诈骗类型：{suspected_type}。",
    ]
    if matched_rules:
        lines.append("命中依据：" + "；".join(matched_rules[:6]) + "。")
    if advice:
        lines.append("建议：" + "；".join(advice[:4]))
    return "\n".join(lines)
