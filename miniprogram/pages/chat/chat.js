const api = require("../../utils/api");
const audio = require("../../utils/audio");
const records = require("../../utils/records");

const recorder = wx.getRecorderManager();
const SESSION_LIMIT = 30;
const TOPBAR_EXTRA_OFFSET = 12;
const TOP_INSIGHT_COLLAPSED_HEIGHT_RPX = 88;
const TOP_INSIGHT_EXPANDED_HEIGHT_RPX = 324;
const WELCOME_TEXT = "你好，我可以帮你判断诈骗风险、解释套路，并给出处置建议。";
const PENDING_CHAT_KEY = "antiFraudMini:pendingChatIntent";
const QUICK_PROMPTS = [
  { text: "我正在被催转账" },
  { text: "帮我判断这是不是诈骗" },
  { text: "讲讲冒充客服骗局" }
];

function asArray(value) {
  if (Array.isArray(value)) return value;
  return value === undefined || value === null || value === "" ? [] : [value];
}

function cleanText(value) {
  return String(value === undefined || value === null ? "" : value).trim();
}

function videoPlayerUrl(sourceUrl, item = {}) {
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

function textFromValue(value) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "object") return cleanText(value);
  return pickFirstText([
    value.label,
    value.rule_name,
    value.name,
    value.title,
    value.summary,
    value.content,
    value.text,
    value.advice
  ]);
}

function compactText(value) {
  return cleanText(value).replace(/\s+/g, "");
}

function normalizeDisplayText(value) {
  return cleanText(value)
    .replace(/\r\n/g, "\n")
    .replace(/^#{1,6}\s*/gm, "")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/^\s*[-*]\s+/gm, "- ")
    .replace(/\n{3,}/g, "\n\n");
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

function asTextList(value) {
  if (Array.isArray(value)) return value.filter(Boolean).map(String);
  if (!value) return [];
  return [String(value)];
}

function reportAnalysisId(analysis) {
  if (!analysis || typeof analysis !== "object") return "";
  return cleanText(
    analysis.analysis_id
    || analysis.id
    || (analysis.report_intel && analysis.report_intel.analysis_id)
  );
}

function navigationMetrics() {
  try {
    const info = wx.getSystemInfoSync ? wx.getSystemInfoSync() : {};
    const menu = wx.getMenuButtonBoundingClientRect ? wx.getMenuButtonBoundingClientRect() : null;
    const statusBarHeight = Number(info.statusBarHeight || 0);
    if (menu && menu.top && menu.height) {
      const gap = Math.max(4, Number(menu.top) - statusBarHeight);
      const windowWidth = Number(info.windowWidth || menu.right || 0);
      const navTop = statusBarHeight + TOPBAR_EXTRA_OFFSET;
      const topbarHeight = Number(menu.height) + gap * 2;
      return {
        navTop,
        topbarHeight,
        navOffset: navTop + topbarHeight,
        menuTop: navTop,
        rightSafe: Math.max(0, windowWidth - Number(menu.left || 0) + gap)
      };
    }
    const navTop = statusBarHeight + TOPBAR_EXTRA_OFFSET;
    return {
      navTop,
      topbarHeight: 48,
      navOffset: navTop + 48,
      menuTop: navTop,
      rightSafe: 0
    };
  } catch (error) {
    return {
      navTop: 36,
      topbarHeight: 48,
      navOffset: 84,
      menuTop: 36,
      rightSafe: 0
    };
  }
}

function nested(object, path) {
  return path.split(".").reduce((current, key) => {
    if (!current || typeof current !== "object") return undefined;
    return current[key];
  }, object);
}

function isInternalDiagnostic(value) {
  const text = cleanText(value);
  return !text
    || /fallback_after_route_error|route_error_fallback|LLM route unavailable|LLM scene router|ValueError|Traceback|Exception/i.test(text)
    || text.includes("暂无明确命中依据");
}

function isUnknownText(value) {
  return /未知|unknown|none|undefined|null/i.test(cleanText(value));
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

function isRiskResponse(data) {
  const summary = responseSummary(data);
  const engine = responseEngine(data);
  const routeDecision = (data && data.route_decision) || summary.route_decision || {};
  const card = responseRiskCard(data);
  const levelName = pickFirstText([nested(card, "risk_level.name"), data && data.risk_level, summary.risk_level, engine.risk_level_name]);
  const score = Number(pickFirstText([nested(card, "risk_level.score"), data && data.risk_score, summary.risk_score, engine.risk_score]) || 0);
  const sceneName = pickFirstText([nested(card, "risk_scene.name"), data && data.fraud_type, summary.fraud_type, engine.risk_scene_name]);
  const features = extractEvidenceLines(data);
  return (data && data.assistant_mode) === "risk_dissuasion"
    || summary.assistant_mode === "risk_dissuasion"
    || (data && data.workflow_mode) === "risk_case_flow"
    || summary.workflow_mode === "risk_case_flow"
    || routeDecision.workflow_mode === "risk_case_flow"
    || score > 0
    || (levelName && !/未知|unknown/i.test(levelName))
    || (sceneName && !/未知|unknown/i.test(sceneName))
    || features.length > 0;
}

function isRiskMeta(meta) {
  const workflowMode = cleanText(meta && (meta.workflowMode || meta.workflow_mode));
  const assistantMode = cleanText(meta && (meta.assistantMode || meta.assistant_mode));
  const routeDecision = (meta && meta.routeDecision) || {};
  return assistantMode === "risk_dissuasion"
    || workflowMode === "risk_case_flow"
    || cleanText(routeDecision.workflow_mode) === "risk_case_flow";
}

function defaultTopInsight() {
  return {
    type: "knowledge",
    title: "反诈科普",
    badge: "当前咨询",
    tone: "normal",
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

function topInsightFromRiskCard(riskCard, meta = {}) {
  const riskMode = Boolean(riskCard) || isRiskMeta(meta);
  if (!riskMode) return defaultTopInsight();
  const card = riskCard || {};
  const tone = card.tone || "high";
  const level = cleanText(card.level) || "风险待确认";
  const scene = cleanText(card.scene) || "风险场景待补充";
  const stage = cleanText(card.stage) || "事实补充中";
  const features = asTextList(card.features).slice(0, 5);
  const rules = asTextList(card.rules).slice(0, 4);
  const actions = asTextList(card.actions).slice(0, 5);
  const hasDetails = Boolean(
    riskCard
    && (level || scene || stage || card.scoreText || card.evidenceSummary || features.length || rules.length || actions.length)
  );
  return {
    type: "risk",
    title: "风险劝阻提醒",
    badge: tone === "critical" || tone === "high" ? "高风险提醒" : "风险提醒",
    tone,
    level,
    scoreText: cleanText(card.scoreText),
    scene,
    stage,
    evidenceSummary: cleanText(card.evidenceSummary),
    features,
    rules,
    actions,
    hasDetails
  };
}

function topInsightFromMessages(messages, meta = {}) {
  const source = stripDefaultWelcome(messages);
  for (let index = source.length - 1; index >= 0; index -= 1) {
    const item = source[index];
    if (item && item.role === "bot" && (item.riskCard || isRiskMeta(item.meta))) {
      return topInsightFromRiskCard(item.riskCard, item.meta);
    }
  }
  return isRiskMeta(meta) ? topInsightFromRiskCard(null, meta) : defaultTopInsight();
}

function topInsightView(topInsight, expanded = false) {
  const nextExpanded = Boolean(expanded && topInsight && topInsight.hasDetails);
  return {
    topInsight: topInsight || defaultTopInsight(),
    topInsightExpanded: nextExpanded,
    topInsightHeightRpx: nextExpanded ? TOP_INSIGHT_EXPANDED_HEIGHT_RPX : TOP_INSIGHT_COLLAPSED_HEIGHT_RPX
  };
}

function responseMetaFromData(data) {
  if (!data || typeof data !== "object") return {};
  const summary = responseSummary(data);
  const engine = responseEngine(data);
  const routeDecision = data.route_decision || summary.route_decision || {};
  const assistantMode = data.assistant_mode || summary.assistant_mode || "";
  const workflowMode = data.workflow_mode || summary.workflow_mode || routeDecision.workflow_mode || "";
  return {
    assistantMode,
    workflowMode,
    routeDecision,
    antiFraudEngine: engine,
    riskJudgementCard: responseRiskCard(data),
    topics: data.topics || summary.topics || [],
    references: assistantMode === "risk_dissuasion" ? [] : (data.references || []),
    source: data.source || summary.source || "",
    emergency: assistantMode === "risk_dissuasion" || workflowMode === "risk_case_flow" ? data : null
  };
}

function videoCardsFromResponse(data) {
  const summary = responseSummary(data);
  const cards = (data && data.video_cards) || summary.video_cards || [];
  if (!Array.isArray(cards)) return [];
  return cards
    .filter((item) => item && typeof item === "object" && /^https?:\/\//i.test(cleanText(item.source_url)))
    .slice(0, 3)
    .map((item) => {
      const durationSeconds = Number(item.duration_seconds || 0);
      const minutes = Math.floor(durationSeconds / 60);
      const seconds = String(durationSeconds % 60).padStart(2, "0");
      const player = videoPlayerUrl(item.source_url, item);
      return {
        videoId: cleanText(item.video_id),
        scamId: cleanText(item.scam_id),
        title: cleanText(item.title) || "官方反诈视频",
        coverUrl: cleanText(item.cover_url),
        sourceUrl: cleanText(item.source_url),
        publisher: cleanText(item.publisher),
        officialAccount: cleanText(item.official_account),
        platform: cleanText(item.platform),
        durationText: durationSeconds > 0 ? `${minutes}:${seconds}` : "",
        label: cleanText(item.label) || "官方反诈视频",
        playerKind: player.kind,
        playerUrl: player.url,
        playing: false
      };
    });
}

function extractRiskLines(data) {
  const summary = responseSummary(data);
  const engine = responseEngine(data);
  const card = responseRiskCard(data);
  const riskLevel = pickFirstText([
    nested(card, "risk_level.name"),
    data && data.risk_level,
    summary.risk_level,
    engine.risk_level_name,
    engine.risk_level
  ]);
  const riskScore = pickFirstText([
    nested(card, "risk_level.score"),
    data && data.risk_score,
    summary.risk_score,
    engine.risk_score
  ]);
  const riskScene = pickFirstText([
    nested(card, "risk_scene.name"),
    data && data.fraud_type,
    summary.fraud_type,
    engine.risk_scene_name,
    engine.fraud_type
  ]);
  const riskStage = pickFirstText([
    nested(card, "risk_stage.name"),
    data && data.fraud_stage,
    summary.fraud_stage,
    engine.risk_stage_name,
    engine.risk_stage
  ]);
  const functionName = pickFirstText([engine.function_name, data && data.function_name]);
  const showLevel = riskLevel && !isUnknownText(riskLevel);
  const showScene = riskScene && !isUnknownText(riskScene);
  const showStage = riskStage && !isUnknownText(riskStage);
  return [
    showLevel ? `风险等级：${riskScore && riskScore !== "0" ? `${riskLevel}（${riskScore}分）` : riskLevel}` : "",
    showScene ? `风险场景：${riskScene}` : "",
    showStage ? `处置阶段：${riskStage}` : "",
    functionName ? `当前能力：${functionName}` : ""
  ].filter(Boolean);
}

function extractEvidenceLines(data) {
  const summary = responseSummary(data);
  const engine = responseEngine(data);
  const evidence = responseRiskCard(data).evidence || {};
  const features = uniqueTexts(
    []
      .concat(asArray(evidence.features))
      .concat(asArray(data && data.risk_features))
      .concat(asArray(summary.risk_features))
      .concat(asArray(engine.hit_features)),
    5
  );
  const rules = uniqueTexts(
    []
      .concat(asArray(evidence.rules))
      .concat(asArray(data && data.matched_rules))
      .concat(asArray(summary.matched_rules))
      .concat(asArray(engine.matched_rules)),
    4
  );
  const lines = [];
  const evidenceSummary = cleanText(evidence.summary);
  if (!isInternalDiagnostic(evidenceSummary)) lines.push(evidenceSummary);
  if (features.length) lines.push(`风险信号：${features.join("、")}`);
  if (rules.length) lines.push(`命中规则：${rules.join("、")}`);
  return lines;
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

function riskCardFromResponse(data) {
  if (!isRiskResponse(data)) return null;
  const summary = responseSummary(data);
  const engine = responseEngine(data);
  const card = responseRiskCard(data);
  const evidence = card.evidence || {};
  const level = pickFirstText([
    nested(card, "risk_level.name"),
    data && data.risk_level,
    summary.risk_level,
    engine.risk_level_name,
    engine.risk_level
  ]);
  const score = pickFirstText([
    nested(card, "risk_level.score"),
    data && data.risk_score,
    summary.risk_score,
    engine.risk_score
  ]);
  const scene = pickFirstText([
    nested(card, "risk_scene.name"),
    data && data.fraud_type,
    data && data.scam_type,
    summary.fraud_type,
    engine.risk_scene_name,
    engine.fraud_type
  ]);
  const stage = pickFirstText([
    nested(card, "risk_stage.name"),
    data && data.fraud_stage,
    summary.fraud_stage,
    engine.risk_stage_name,
    engine.risk_stage
  ]);
  const features = uniqueTexts(
    []
      .concat(asArray(evidence.features))
      .concat(asArray(data && data.risk_features))
      .concat(asArray(summary.risk_features))
      .concat(asArray(engine.hit_features)),
    5
  );
  const rules = uniqueTexts(
    []
      .concat(asArray(evidence.rules))
      .concat(asArray(data && data.matched_rules))
      .concat(asArray(summary.matched_rules))
      .concat(asArray(engine.matched_rules)),
    4
  );
  const evidenceSummary = isInternalDiagnostic(evidence.summary) ? "" : normalizeDisplayText(evidence.summary);
  const actions = extractActionLines(data).map(normalizeDisplayText).filter(Boolean).slice(0, 5);
  const scoreNumber = Number(score || 0);
  const hasSignal = Boolean(
    (level && !isUnknownText(level))
    || scoreNumber
    || (scene && !isUnknownText(scene))
    || (stage && !isUnknownText(stage))
    || evidenceSummary
    || features.length
    || rules.length
    || actions.length
  );
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
    expanded: false,
    hasDetails: Boolean(evidenceSummary || features.length || rules.length || actions.length),
    tone: scoreNumber >= 80 ? "critical" : scoreNumber >= 60 ? "high" : scoreNumber >= 30 ? "medium" : "normal"
  };
}

function answerFromResponse(data) {
  if (!data) return "没有收到回复。";
  const answer = pickFirstText([
    data.answer,
    data.reply,
    data.response,
    data.content,
    data.result && typeof data.result === "string" ? data.result : ""
  ]);
  return normalizeDisplayText(answer || "已完成研判，下面是重点结果。");
}

function newMessage(role, text, extra = {}) {
  return {
    id: `m${Date.now()}-${Math.random().toString(16).slice(2, 7)}`,
    role,
    text,
    ...extra
  };
}

function welcomeMessage(text = WELCOME_TEXT) {
  return {
    id: "m0",
    role: "bot",
    text
  };
}

function isDefaultWelcomeMessage(item) {
  return Boolean(item && item.role === "bot" && item.id === "m0");
}

function stripDefaultWelcome(messages) {
  return (Array.isArray(messages) ? messages : []).filter((item) => !isDefaultWelcomeMessage(item));
}

function chatViewFromMessages(messages) {
  const source = Array.isArray(messages) ? messages : [];
  const displayMessages = stripDefaultWelcome(source);
  const last = displayMessages[displayMessages.length - 1] || source[source.length - 1] || welcomeMessage();
  return {
    displayMessages,
    showWelcome: displayMessages.length === 0,
    lastMessageId: last.id || "m0"
  };
}

function titleFromMessages(messages) {
  const firstUser = (messages || []).find((item) => item.role === "user" && String(item.text || "").trim());
  const text = firstUser ? String(firstUser.text || "").trim() : "新对话";
  return text.length > 18 ? `${text.slice(0, 18)}...` : text;
}

function chatHistoryItem(item) {
  return {
    role: item.role === "bot" ? "assistant" : "user",
    content: item.text || ""
  };
}

function knowledgeHistory(messages) {
  messages = stripDefaultWelcome(messages);
  const current = messages[messages.length - 1] || {};
  const text = compactText(current.text);
  const followupMarkers = ["那", "这个", "这种", "刚才", "上面", "前面", "它", "继续", "还有", "怎么防", "如何防", "案例", "法律", "总结", "套路"];
  const standaloneMarkers = ["什么是", "是什么", "介绍", "科普", "讲讲", "我最近", "我看到", "我想咨询", "咨询一件事", "可以买吗", "能买吗", "靠谱吗", "靠不靠谱"];
  const hasStandaloneMarker = standaloneMarkers.some((item) => text.includes(item));
  const shouldSendHistory = !hasStandaloneMarker && (text.length <= 8 || followupMarkers.some((item) => text.includes(item)));
  if (!shouldSendHistory) return [];
  return messages
    .filter((item) => item.role === "user" || item.role === "bot")
    .slice(-4)
    .slice(0, -1)
    .map(chatHistoryItem);
}

function riskConversationHistory(messages) {
  return stripDefaultWelcome(messages)
    .filter((item) => (item.role === "user" || item.role === "bot") && cleanText(item.text))
    .slice(-13)
    .slice(0, -1)
    .map(chatHistoryItem);
}

function buildChatHistory(messages, meta) {
  if (isRiskMeta(meta)) return riskConversationHistory(messages);
  return knowledgeHistory(messages);
}

function analyzeVoiceEmotion(text) {
  const raw = String(text || "");
  if (/救命|害怕|被骗|完了|怎么办|来不及|报警|转账|验证码|屏幕共享/.test(raw)) {
    return {
      key: "urgent",
      label: "紧急",
      confidence: 0.78,
      agentTone: "先安抚，再给出最短止损步骤",
      source: "mini_voice_text"
    };
  }
  if (/不确定|是不是|真的吗|靠谱吗|可以吗|风险/.test(raw)) {
    return {
      key: "confused",
      label: "疑惑",
      confidence: 0.64,
      agentTone: "解释判断依据，给出核实方法",
      source: "mini_voice_text"
    };
  }
  return {
    key: "neutral",
    label: "平稳",
    confidence: 0.5,
    agentTone: "自然清楚地回应",
    source: "mini_voice_text"
  };
}

Page({
  loadedUserId: "",
  recordingStartedByChat: false,
  recordStopTimer: null,

  data: {
    inputText: "",
    messages: [welcomeMessage()],
    displayMessages: [],
    showWelcome: true,
    sessions: [],
    activeSessionId: "",
    currentTitle: "新对话",
    quickPrompts: QUICK_PROMPTS,
    menuOpen: false,
    toolPanelOpen: false,
    reportModalOpen: false,
    reportContent: "",
    reportLoading: false,
    reportConfirming: false,
    reportConfirmed: false,
    reportStatusText: "",
    reportError: false,
    reportAnalysis: null,
    reportMatchedRules: [],
    reportAdvice: [],
    reportCanConfirm: false,
    conversationMeta: {},
    sessionId: "",
    sending: false,
    recording: false,
    statusText: "",
    error: false,
    lastMessageId: "m0",
    ...topInsightView(defaultTopInsight(), false),
    ...navigationMetrics()
  },

  onLoad() {
    recorder.onStop(async (res) => {
      if (!this.recordingStartedByChat) return;
      this.recordingStartedByChat = false;
      clearTimeout(this.recordStopTimer);
      this.setData({ recording: false, statusText: "正在识别语音", error: false });
      try {
        const asr = await audio.transcribeAudioFile(res.tempFilePath, { audioFormat: "wav", sampleRate: 16000 });
        const text = String(asr.text || "").trim();
        if (!text) {
          const bytes = asr.meta && asr.meta.audio_bytes ? `，录音 ${Math.round(asr.meta.audio_bytes / 1024)}KB` : "";
          this.setData({ statusText: `没有听清${bytes}。请说一句完整的话，例如“我遇到刷单返利怎么办”。`, error: false });
          return;
        }
        this.setData({ inputText: text, statusText: "语音识别完成，正在发送" });
        await this.sendMessage(text, { inputMode: "voice", voiceEmotion: analyzeVoiceEmotion(text) });
      } catch (error) {
        this.setData({ statusText: error.message, error: true });
      }
    });
    recorder.onError((error) => {
      if (!this.recordingStartedByChat) return;
      this.recordingStartedByChat = false;
      clearTimeout(this.recordStopTimer);
      this.setData({ recording: false, statusText: error.errMsg || "录音失败", error: true });
    });
    this.loadSessions();
  },

  onShow() {
    if (!this.data.activeSessionId || this.loadedUserId !== this.userId()) this.loadSessions();
    this.consumePendingChatIntent();
  },

  onUnload() {
    clearTimeout(this.recordStopTimer);
    if (this.recordingStartedByChat) {
      try {
        recorder.stop();
      } catch (error) {
        this.recordingStartedByChat = false;
      }
    }
  },

  userId() {
    return getApp().globalData.userId || "demo_user";
  },

  sessionStoreKey() {
    return `antiFraudMini:${this.userId()}:chatSessions`;
  },

  activeStoreKey() {
    return `antiFraudMini:${this.userId()}:activeChatSession`;
  },

  blankSession() {
    const now = new Date().toISOString();
    return {
      id: `chat-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      sessionId: "",
      title: "新对话",
      createdAt: now,
      updatedAt: now,
      messages: [welcomeMessage()],
      meta: {}
    };
  },

  readSessions() {
    const sessions = wx.getStorageSync(this.sessionStoreKey());
    return Array.isArray(sessions) ? sessions : [];
  },

  writeSessions(sessions) {
    wx.setStorageSync(this.sessionStoreKey(), sessions.slice(0, SESSION_LIMIT));
  },

  loadSessions() {
    this.loadedUserId = this.userId();
    let sessions = this.readSessions();
    if (!sessions.length) sessions = [this.blankSession()];
    const activeId = wx.getStorageSync(this.activeStoreKey()) || sessions[0].id;
    const active = sessions.find((item) => item.id === activeId) || sessions[0];
    wx.setStorageSync(this.activeStoreKey(), active.id);
    this.writeSessions(sessions);
    const messages = active.messages && active.messages.length ? active.messages : [welcomeMessage()];
    this.setData({
      sessions,
      activeSessionId: active.id,
      currentTitle: active.title || titleFromMessages(messages),
      conversationMeta: active.meta || {},
      sessionId: active.sessionId || "",
      messages,
      ...chatViewFromMessages(messages),
      ...topInsightView(topInsightFromMessages(messages, active.meta || {}), false),
      statusText: "",
      error: false
    });
  },

  persistCurrent(extra = {}) {
    const now = new Date().toISOString();
    const messages = extra.messages || this.data.messages;
    const sessions = this.readSessions().filter((item) => item.id !== this.data.activeSessionId);
    const current = {
      id: this.data.activeSessionId || this.blankSession().id,
      sessionId: extra.sessionId !== undefined ? extra.sessionId : this.data.sessionId,
      title: titleFromMessages(messages),
      createdAt: extra.createdAt || new Date().toISOString(),
      updatedAt: now,
      messages,
      meta: extra.meta !== undefined ? extra.meta : (this.data.conversationMeta || {})
    };
    const old = this.readSessions().find((item) => item.id === current.id);
    if (old && old.createdAt) current.createdAt = old.createdAt;
    const next = [current].concat(sessions).slice(0, SESSION_LIMIT);
    this.writeSessions(next);
    wx.setStorageSync(this.activeStoreKey(), current.id);
    this.setData({ sessions: next, activeSessionId: current.id, currentTitle: current.title });
  },

  onInput(event) {
    this.setData({ inputText: event.detail.value });
  },

  useQuickPrompt(event) {
    const prompt = event.currentTarget.dataset.prompt || "";
    this.setData({ inputText: prompt });
  },

  consumePendingChatIntent() {
    const pending = wx.getStorageSync(PENDING_CHAT_KEY);
    if (!pending || typeof pending !== "object") return;
    wx.removeStorageSync(PENDING_CHAT_KEY);
    const prompt = cleanText(pending.prompt);
    this.setData({
      inputText: prompt || this.data.inputText
    });
  },

  noop() {},

  openMenu() {
    this.setData({ menuOpen: true, toolPanelOpen: false });
  },

  closeMenu() {
    this.setData({ menuOpen: false });
  },

  goTraining() {
    this.closeMenu();
    wx.navigateTo({ url: "/pages/training/training" });
  },

  playVideoCard(event) {
    const target = event && event.currentTarget;
    const dataset = (target && target.dataset) || {};
    const messageIndex = Number(dataset.messageIndex);
    const videoIndex = Number(dataset.videoIndex);
    const card = this.data.displayMessages?.[messageIndex]?.videoCards?.[videoIndex] || {};
    const player = videoPlayerUrl(card.sourceUrl, card);
    if (player.url) {
      const path = `displayMessages[${messageIndex}].videoCards[${videoIndex}]`;
      const changes = {
        [`${path}.playing`]: true
      };
      if (!card.playerUrl) {
        changes[`${path}.playerKind`] = player.kind;
        changes[`${path}.playerUrl`] = player.url;
      }
      this.setData(changes);
      return;
    }
    this.openOfficialVideo(card);
  },

  stopVideoTap() {},

  openOfficialVideo(eventOrCard) {
    const card = eventOrCard && eventOrCard.currentTarget
      ? eventOrCard.currentTarget.dataset.card || {}
      : eventOrCard || {};
    const sourceUrl = cleanText(card.sourceUrl);
    if (!/^https?:\/\//i.test(sourceUrl)) {
      wx.showToast({ title: "官方链接暂不可用", icon: "none" });
      return;
    }
    wx.navigateTo({
      url: `/pages/video-webview/video-webview?url=${encodeURIComponent(sourceUrl)}`
    });
  },

  goSimulation() {
    this.closeMenu();
    wx.navigateTo({ url: "/pages/simulation/simulation" });
  },

  toggleToolPanel() {
    this.setData({ toolPanelOpen: !this.data.toolPanelOpen, menuOpen: false });
  },

  closeToolPanel() {
    this.setData({ toolPanelOpen: false });
  },

  newChat() {
    const currentMessages = stripDefaultWelcome(this.data.messages);
    if (!currentMessages.length) {
      this.setData({ menuOpen: false, toolPanelOpen: false });
      wx.showToast({
        title: "目前已经在新对话了",
        icon: "none",
        duration: 1400
      });
      return;
    }
    const session = this.blankSession();
    const sessions = [session].concat(this.readSessions()).slice(0, SESSION_LIMIT);
    this.writeSessions(sessions);
    wx.setStorageSync(this.activeStoreKey(), session.id);
    this.setData({
      inputText: "",
      messages: session.messages,
      ...chatViewFromMessages(session.messages),
      ...topInsightView(defaultTopInsight(), false),
      sessions,
      menuOpen: false,
      toolPanelOpen: false,
      activeSessionId: session.id,
      currentTitle: session.title,
      conversationMeta: session.meta || {},
      sessionId: "",
      statusText: "",
      error: false
    });
  },

  openSession(event) {
    const id = event.currentTarget.dataset.id;
    const sessions = this.readSessions();
    const session = sessions.find((item) => item.id === id);
    if (!session) return;
    const messages = session.messages && session.messages.length ? session.messages : [welcomeMessage()];
    wx.setStorageSync(this.activeStoreKey(), id);
    this.setData({
      inputText: "",
      messages,
      ...chatViewFromMessages(messages),
      ...topInsightView(topInsightFromMessages(messages, session.meta || {}), false),
      sessions,
      menuOpen: false,
      toolPanelOpen: false,
      activeSessionId: id,
      currentTitle: session.title || titleFromMessages(messages),
      conversationMeta: session.meta || {},
      sessionId: session.sessionId || "",
      statusText: "",
      error: false
    });
  },

  deleteSession(event) {
    const id = event.currentTarget.dataset.id;
    let sessions = this.readSessions().filter((item) => item.id !== id);
    if (!sessions.length) sessions = [this.blankSession()];
    this.writeSessions(sessions);
    const next = sessions[0];
    wx.setStorageSync(this.activeStoreKey(), next.id);
    const messages = next.messages && next.messages.length ? next.messages : [welcomeMessage()];
    this.setData({
      inputText: "",
      messages,
      ...chatViewFromMessages(messages),
      ...topInsightView(topInsightFromMessages(messages, next.meta || {}), false),
      sessions,
      activeSessionId: next.id,
      currentTitle: next.title || titleFromMessages(messages),
      conversationMeta: next.meta || {},
      sessionId: next.sessionId || ""
    });
  },

  async sendMessage(textOverride = "", options = {}) {
    const providedText = typeof textOverride === "string" ? textOverride : "";
    const text = String(providedText || this.data.inputText || "").trim();
    if (!text || this.data.sending) return;
    const existingMessages = stripDefaultWelcome(this.data.messages);
    const userMessage = newMessage("user", text, {
      inputMode: options.inputMode || "text",
      voiceEmotion: options.voiceEmotion || null
    });
    const messages = existingMessages.concat(userMessage);
    this.setData({
      messages,
      ...chatViewFromMessages(messages),
      inputText: "",
      sending: true,
      statusText: options.inputMode === "voice" ? "语音已转文字，正在研判" : "正在研判",
      error: false
    });
    this.persistCurrent({ messages });

    try {
      const history = buildChatHistory(messages, this.data.conversationMeta);
      const data = await api.post("/knowledge/chat", {
        message: text,
        session_id: this.data.sessionId || undefined,
        history,
        use_llm: true,
        limit: 8,
        is_stream: false,
        input_mode: options.inputMode || "text",
        voice_emotion: options.voiceEmotion || null
      });
      const responseMeta = responseMetaFromData(data);
      const riskCard = riskCardFromResponse(data);
      const botMessage = newMessage("bot", answerFromResponse(data), {
        meta: responseMeta,
        riskCard,
        videoCards: videoCardsFromResponse(data),
        empathyTone: options.voiceEmotion && (options.voiceEmotion.agentTone || options.voiceEmotion.label)
      });
      const nextMessages = messages.concat(botMessage);
      this.setData({
        messages: nextMessages,
        ...chatViewFromMessages(nextMessages),
        ...topInsightView(topInsightFromRiskCard(riskCard, responseMeta), false),
        sessionId: data.session_id || this.data.sessionId,
        conversationMeta: responseMeta,
        statusText: "",
        error: false
      });
      this.persistCurrent({ messages: nextMessages, sessionId: data.session_id || this.data.sessionId, meta: responseMeta });
      records.addRecord("learningRecords", {
        type: options.inputMode === "voice" ? "语音咨询" : "反诈咨询",
        title: titleFromMessages(nextMessages),
        content: text,
        result: botMessage.text
      });
    } catch (error) {
      const botMessage = newMessage("bot", `请求失败：${error.message}`);
      const nextMessages = messages.concat(botMessage);
      this.setData({
        messages: nextMessages,
        ...chatViewFromMessages(nextMessages),
        statusText: error.message,
        error: true
      });
      this.persistCurrent({ messages: nextMessages });
    } finally {
      this.setData({ sending: false });
    }
  },

  toggleTopInsight() {
    const topInsight = this.data.topInsight || defaultTopInsight();
    if (!topInsight.hasDetails) return;
    this.setData(topInsightView(topInsight, !this.data.topInsightExpanded));
  },

  openReportModal() {
    this.setData({
      toolPanelOpen: false,
      reportModalOpen: true,
      reportStatusText: "",
      reportError: false
    });
  },

  closeReportModal() {
    if (this.data.reportLoading || this.data.reportConfirming) return;
    this.setData({ reportModalOpen: false });
  },

  onReportInput(event) {
    this.setData({ reportContent: event.detail.value });
  },

  clearReportTool() {
    if (this.data.reportLoading || this.data.reportConfirming) return;
    this.setData({
      reportContent: "",
      reportStatusText: "",
      reportError: false,
      reportAnalysis: null,
      reportMatchedRules: [],
      reportAdvice: [],
      reportCanConfirm: false,
      reportConfirmed: false
    });
  },

  async analyzeReportTool() {
    const content = cleanText(this.data.reportContent);
    if (!content || this.data.reportLoading) return;
    this.setData({
      reportLoading: true,
      reportStatusText: "正在研判",
      reportError: false,
      reportConfirmed: false
    });
    try {
      const analysis = await api.post("/report-intel/analyze", { content });
      this.setData({
        reportAnalysis: analysis,
        reportMatchedRules: asTextList(analysis.matched_rules),
        reportAdvice: asTextList(analysis.advice),
        reportCanConfirm: Boolean(reportAnalysisId(analysis)),
        reportStatusText: analysis.message || "研判完成",
        reportError: false
      });
      records.addRecord("reportRecords", {
        type: "举报研判",
        title: analysis.suspected_type || analysis.fraud_type || analysis.risk_level || "研判结果",
        content,
        result: analysis.display_summary || analysis.answer || analysis.message || ""
      });
    } catch (error) {
      this.setData({ reportStatusText: error.message, reportError: true });
    } finally {
      this.setData({ reportLoading: false });
    }
  },

  async confirmReportTool() {
    const analysis = this.data.reportAnalysis;
    const analysisId = reportAnalysisId(analysis);
    if (!analysis || !analysisId || this.data.reportConfirming) {
      if (analysis && !analysisId) this.setData({ reportStatusText: "当前研判缺少编号，请重新研判后再确认举报", reportError: true });
      return;
    }
    this.setData({ reportConfirming: true, reportStatusText: "正在确认举报", reportError: false });
    try {
      const data = await api.post("/report-intel/confirm", {
        analysis_id: analysisId,
        reporter_note: "来自微信小程序聊天页确认"
      });
      this.setData({
        reportConfirmed: true,
        reportStatusText: data.report_id ? `举报已确认：${data.report_id}` : data.message || "举报已确认",
        reportError: false
      });
      records.addRecord("reportRecords", {
        type: "确认举报",
        title: data.report_id || "举报已确认",
        content: this.data.reportContent,
        result: data.message || "举报已确认"
      });
    } catch (error) {
      this.setData({ reportStatusText: error.message, reportError: true });
    } finally {
      this.setData({ reportConfirming: false });
    }
  },

  toggleRecord() {
    if (this.recordingStartedByChat || this.data.recording) {
      this.stopRecord();
      return;
    }
    this.startRecord();
  },

  async startRecord() {
    clearTimeout(this.recordStopTimer);
    try {
      this.setData({ statusText: "正在请求麦克风权限", error: false });
      await audio.ensureRecordPermission();
      this.recordingStartedByChat = true;
      this.setData({ recording: true, statusText: "正在录音，说完后点停止", error: false });
      recorder.start({
        duration: 15000,
        sampleRate: 16000,
        numberOfChannels: 1,
        encodeBitRate: 64000,
        format: "wav"
      });
    } catch (error) {
      this.recordingStartedByChat = false;
      this.setData({ recording: false, statusText: error.errMsg || error.message || "录音启动失败", error: true });
    }
  },

  stopRecord() {
    this.setData({ recording: false, statusText: "正在停止录音", error: false });
    try {
      recorder.stop();
    } catch (error) {
      this.recordingStartedByChat = false;
      this.setData({ statusText: error.errMsg || error.message || "录音已停止", error: Boolean(error.errMsg || error.message) });
      return;
    }
    clearTimeout(this.recordStopTimer);
    this.recordStopTimer = setTimeout(() => {
      if (this.data.statusText === "正在停止录音") {
        this.setData({ statusText: "录音已停止，等待识别结果" });
      }
    }, 1200);
  }
});
