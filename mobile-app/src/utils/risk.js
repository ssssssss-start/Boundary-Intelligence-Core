function asArray(value) {
  if (Array.isArray(value)) return value;
  return value === undefined || value === null || value === "" ? [] : [value];
}

export function cleanText(value) {
  return String(value === undefined || value === null ? "" : value).trim();
}

function textFromValue(value) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "object") return cleanText(value);
  return pickFirstText([value.label, value.rule_name, value.name, value.title, value.summary, value.content, value.text, value.advice]);
}

function pickFirstText(values) {
  return values.map(cleanText).find(Boolean) || "";
}

function uniqueTexts(values, limit = 6) {
  const seen = {};
  const result = [];
  asArray(values).forEach((item) => {
    const text = textFromValue(item);
    if (!text || seen[text]) return;
    seen[text] = true;
    result.push(text);
  });
  return result.slice(0, limit);
}

function nested(object, path) {
  return path.split(".").reduce((current, key) => {
    if (!current || typeof current !== "object") return undefined;
    return current[key];
  }, object);
}

function responseSummary(data) {
  return (data && data.summary) || {};
}

function responseEngine(data) {
  const summary = responseSummary(data);
  return (data && data.anti_fraud_engine) || summary.anti_fraud_engine || {};
}

function responseRiskCard(data) {
  const summary = responseSummary(data);
  const engine = responseEngine(data);
  return (data && data.risk_judgement_card) || summary.risk_judgement_card || engine.risk_judgement_card || {};
}

function isUnknownText(value) {
  return /未知|unknown|none|undefined|null/i.test(cleanText(value));
}

function isInternalDiagnostic(value) {
  const text = cleanText(value);
  return !text || /fallback_after_route_error|route_error_fallback|LLM route unavailable|ValueError|Traceback|Exception/i.test(text) || text.includes("暂无明确命中依据");
}

export function normalizeDisplayText(value) {
  return cleanText(value)
    .replace(/\r\n/g, "\n")
    .replace(/^#{1,6}\s*/gm, "")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/^\s*[-*]\s+/gm, "- ")
    .replace(/\n{3,}/g, "\n\n");
}

export function isRiskMeta(meta) {
  const workflowMode = cleanText(meta && (meta.workflowMode || meta.workflow_mode));
  const assistantMode = cleanText(meta && (meta.assistantMode || meta.assistant_mode));
  const routeDecision = (meta && meta.routeDecision) || {};
  return assistantMode === "risk_dissuasion" || workflowMode === "risk_case_flow" || cleanText(routeDecision.workflow_mode) === "risk_case_flow";
}

export function responseMetaFromData(data) {
  if (!data || typeof data !== "object") return {};
  const summary = responseSummary(data);
  const routeDecision = data.route_decision || summary.route_decision || {};
  const assistantMode = data.assistant_mode || summary.assistant_mode || "";
  const workflowMode = data.workflow_mode || summary.workflow_mode || routeDecision.workflow_mode || "";
  return {
    assistantMode,
    workflowMode,
    routeDecision,
    riskJudgementCard: responseRiskCard(data),
    source: data.source || summary.source || ""
  };
}

export function videoPlayerInfo(sourceUrl, item = {}) {
  const directUrl = cleanText(item.video_url || item.media_url);
  if (/^https?:\/\//i.test(directUrl)) return { kind: "video", url: directUrl };
  const embedUrl = cleanText(item.embed_url || item.player_url);
  if (/^https?:\/\//i.test(embedUrl)) return { kind: "webview", url: embedUrl };
  const match = cleanText(sourceUrl).match(/\b(BV[0-9A-Za-z]+)\b/);
  if (!match) return { kind: "", url: "" };
  return {
    kind: "webview",
    url: `https://player.bilibili.com/player.html?bvid=${match[1]}&page=1&autoplay=1&high_quality=1`
  };
}

export function videoCardsFromResponse(data) {
  const summary = responseSummary(data);
  const cards = data?.video_cards || summary.video_cards || [];
  if (!Array.isArray(cards)) return [];
  return cards
    .filter((item) => item && typeof item === "object" && cleanText(item.source_url))
    .slice(0, 3)
    .map((item) => {
      const sourceUrl = cleanText(item.source_url);
      const player = videoPlayerInfo(sourceUrl, item);
      return {
        videoId: cleanText(item.video_id),
        scamId: cleanText(item.scam_id),
        title: cleanText(item.title) || "官方反诈视频",
        coverUrl: cleanText(item.cover_url),
        sourceUrl,
        publisher: cleanText(item.publisher),
        officialAccount: cleanText(item.official_account),
        platform: cleanText(item.platform),
        durationSeconds: Number(item.duration_seconds || 0),
        orientation: cleanText(item.orientation) || "vertical",
        label: cleanText(item.label) || "官方反诈视频",
        playerKind: player.kind,
        playerUrl: player.url
      };
    });
}

function extractActionLines(data) {
  const summary = responseSummary(data);
  const intervention = (data && data.intervention) || summary.intervention || {};
  const resolution = (data && data.resolution) || summary.resolution || {};
  return uniqueTexts(
    []
      .concat(asArray(data && data.advice))
      .concat(asArray(data && data.recommended_actions))
      .concat(asArray(data && data.pending_resolution_actions))
      .concat(asArray(summary.recommended_actions))
      .concat(asArray(summary.pending_resolution_actions))
      .concat(asArray(intervention.advice))
      .concat(asArray(intervention.action_plan))
      .concat(asArray(resolution.next_actions))
      .concat(asArray(nested(responseRiskCard(data), "action_plan"))),
    5
  );
}

function isRiskResponse(data) {
  const summary = responseSummary(data);
  const engine = responseEngine(data);
  const routeDecision = (data && data.route_decision) || summary.route_decision || {};
  const card = responseRiskCard(data);
  const levelName = pickFirstText([nested(card, "risk_level.name"), data && data.risk_level, summary.risk_level, engine.risk_level_name]);
  const score = Number(pickFirstText([nested(card, "risk_level.score"), data && data.risk_score, summary.risk_score, engine.risk_score]) || 0);
  const sceneName = pickFirstText([nested(card, "risk_scene.name"), data && data.fraud_type, summary.fraud_type, engine.risk_scene_name]);
  return (data && data.assistant_mode) === "risk_dissuasion"
    || summary.assistant_mode === "risk_dissuasion"
    || (data && data.workflow_mode) === "risk_case_flow"
    || summary.workflow_mode === "risk_case_flow"
    || routeDecision.workflow_mode === "risk_case_flow"
    || score > 0
    || (levelName && !isUnknownText(levelName))
    || (sceneName && !isUnknownText(sceneName));
}

export function riskCardFromResponse(data) {
  if (!isRiskResponse(data)) return null;
  const summary = responseSummary(data);
  const engine = responseEngine(data);
  const card = responseRiskCard(data);
  const evidence = card.evidence || {};
  const level = pickFirstText([nested(card, "risk_level.name"), data && data.risk_level, summary.risk_level, engine.risk_level_name, engine.risk_level]);
  const score = pickFirstText([nested(card, "risk_level.score"), data && data.risk_score, summary.risk_score, engine.risk_score]);
  const scene = pickFirstText([nested(card, "risk_scene.name"), data && data.fraud_type, data && data.scam_type, summary.fraud_type, engine.risk_scene_name, engine.fraud_type]);
  const stage = pickFirstText([nested(card, "risk_stage.name"), data && data.fraud_stage, summary.fraud_stage, engine.risk_stage_name, engine.risk_stage]);
  const features = uniqueTexts([].concat(asArray(evidence.features)).concat(asArray(data && data.risk_features)).concat(asArray(summary.risk_features)).concat(asArray(engine.hit_features)), 5);
  const rules = uniqueTexts([].concat(asArray(evidence.rules)).concat(asArray(data && data.matched_rules)).concat(asArray(summary.matched_rules)).concat(asArray(engine.matched_rules)), 4);
  const evidenceSummary = isInternalDiagnostic(evidence.summary) ? "" : normalizeDisplayText(evidence.summary);
  const actions = extractActionLines(data).map(normalizeDisplayText).filter(Boolean).slice(0, 5);
  const scoreNumber = Number(score || 0);
  const hasSignal = Boolean((level && !isUnknownText(level)) || scoreNumber || (scene && !isUnknownText(scene)) || (stage && !isUnknownText(stage)) || evidenceSummary || features.length || rules.length || actions.length);
  if (!hasSignal) return null;
  return {
    level: level && !isUnknownText(level) ? level : "风险待确认",
    scoreText: score && score !== "0" ? String(score) : "",
    scene: scene && !isUnknownText(scene) ? scene : "风险场景待补充",
    stage: stage && !isUnknownText(stage) ? stage : "事实补充中",
    evidenceSummary,
    features,
    rules,
    actions,
    tone: scoreNumber >= 80 ? "critical" : scoreNumber >= 60 ? "high" : scoreNumber >= 30 ? "medium" : "normal"
  };
}

export function answerFromResponse(data) {
  if (!data) return "没有收到回复。";
  const answer = pickFirstText([data.answer, data.reply, data.response, data.content, data.result && typeof data.result === "string" ? data.result : ""]);
  return normalizeDisplayText(answer || "已完成研判，下面是重点结果。");
}

export function defaultTopInsight() {
  return {
    type: "knowledge",
    title: "反诈科普",
    badge: "当前咨询",
    level: "",
    scoreText: "",
    scene: "",
    stage: "",
    evidenceSummary: "",
    features: [],
    rules: [],
    actions: [],
    hasDetails: false
  };
}

export function topInsightFromRiskCard(riskCard, meta = {}) {
  const riskMode = Boolean(riskCard) || isRiskMeta(meta);
  if (!riskMode) return defaultTopInsight();
  const card = riskCard || {};
  const features = Array.isArray(card.features) ? card.features.slice(0, 5) : [];
  const rules = Array.isArray(card.rules) ? card.rules.slice(0, 4) : [];
  const actions = Array.isArray(card.actions) ? card.actions.slice(0, 5) : [];
  return {
    type: "risk",
    title: "风险劝阻提醒",
    badge: "高风险提醒",
    level: cleanText(card.level) || "风险待确认",
    scoreText: cleanText(card.scoreText),
    scene: cleanText(card.scene) || "风险场景待补充",
    stage: cleanText(card.stage) || "事实补充中",
    evidenceSummary: cleanText(card.evidenceSummary),
    features,
    rules,
    actions,
    hasDetails: Boolean(riskCard)
  };
}
