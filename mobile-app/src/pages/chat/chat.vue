<template>
  <view class="screen" :style="{ paddingTop: navTop + 'px' }">
    <view class="topbar" :style="{ height: topbarHeight + 'px' }">
      <button class="top-action menu-action" @tap="openMenu">...</button>
      <view class="top-title">反诈助手</view>
      <button class="top-action new-action" @tap="newChat">＋</button>
    </view>

    <view class="top-insight" :class="[topInsight.type, topInsightExpanded ? 'expanded' : '']" @tap="toggleTopInsight">
      <view class="top-insight-row">
        <view class="top-insight-title">{{ topInsight.title }}</view>
        <view class="top-insight-badge">{{ topInsight.badge }}</view>
      </view>
      <view v-if="topInsightExpanded && topInsight.hasDetails" class="top-insight-detail">
        <view class="top-insight-grid">
          <view class="top-insight-cell">
            <text>等级</text>
            <strong>{{ topInsight.level }}</strong>
          </view>
          <view class="top-insight-cell">
            <text>场景</text>
            <strong>{{ topInsight.scene }}</strong>
          </view>
          <view class="top-insight-cell">
            <text>阶段</text>
            <strong>{{ topInsight.stage }}</strong>
          </view>
          <view v-if="topInsight.scoreText" class="top-insight-cell">
            <text>风险分</text>
            <strong>{{ topInsight.scoreText }}</strong>
          </view>
        </view>
        <view v-if="topInsight.evidenceSummary" class="top-insight-summary">{{ topInsight.evidenceSummary }}</view>
        <view v-if="topInsight.features.length" class="top-insight-list">
          <view class="top-insight-list-title">风险信号</view>
          <view v-for="item in topInsight.features" :key="item" class="top-insight-item">{{ item }}</view>
        </view>
        <view v-if="topInsight.rules.length" class="top-insight-list">
          <view class="top-insight-list-title">命中依据</view>
          <view v-for="item in topInsight.rules" :key="item" class="top-insight-item">{{ item }}</view>
        </view>
        <view v-if="topInsight.actions.length" class="top-insight-list">
          <view class="top-insight-list-title">下一步建议</view>
          <view v-for="(item, index) in topInsight.actions" :key="item" class="top-insight-item">{{ index + 1 }}. {{ item }}</view>
        </view>
      </view>
    </view>

    <view v-if="menuOpen" class="menu-mask" @tap="closeMenu">
      <view class="side-menu" :style="menuStyle" @tap.stop>
        <view class="menu-section">
          <view class="menu-item" @tap="goTraining">
            <view class="menu-dot">训</view>
            <view class="menu-copy">
              <view class="menu-title">防骗训练营</view>
              <view class="menu-subtitle">闯关答题提升识别力</view>
            </view>
          </view>
          <view class="menu-item" @tap="goSimulation">
            <view class="menu-dot">练</view>
            <view class="menu-copy">
              <view class="menu-title">骗局模拟</view>
              <view class="menu-subtitle">和话术对练并评分</view>
            </view>
          </view>
        </view>
        <view class="history-head">历史聊天</view>
        <scroll-view class="history-list" scroll-y>
          <view
            v-for="item in sessions"
            :key="item.id"
            class="history-row"
            :class="{ active: item.id === activeSessionId }"
            @tap="openSession(item.id)"
          >
            <view class="history-title">{{ item.title || '新对话' }}</view>
            <view class="history-meta">{{ (item.messages || []).length }} 条消息</view>
          </view>
        </scroll-view>
      </view>
    </view>

    <scroll-view class="messages" :class="{ 'is-empty': showWelcome }" :style="messagesStyle" scroll-y scroll-with-animation :scroll-into-view="lastMessageId">
      <view v-if="showWelcome" class="welcome-panel">
        <view class="welcome-mark"></view>
        <view class="welcome-title">有什么可以帮忙的？</view>
        <view class="welcome-copy">描述对方让你做什么，或粘贴可疑话术。我会帮你判断风险并给出下一步。</view>
        <view class="welcome-prompts">
          <button v-for="item in quickPrompts" :key="item.text" class="welcome-chip" @tap="useQuickPrompt(item.text)">{{ item.text }}</button>
        </view>
      </view>
      <template v-else>
        <view v-for="item in displayMessages" :id="item.id" :key="item.id" class="message" :class="item.role">
          <view class="bubble-wrap">
            <view class="bubble">{{ item.text }}</view>
            <view v-if="item.role === 'bot' && item.videoCards && item.videoCards.length" class="video-card-list">
              <view
                v-for="card in item.videoCards"
                :key="card.videoId || card.sourceUrl"
                class="video-card"
              >
                <view v-if="isVideoPlaying(card)" class="video-card-inline-player" @tap.stop>
                  <video v-if="card.playerKind === 'video'" class="video-card-video" :src="card.playerUrl" controls autoplay playsinline object-fit="contain" />
                  <web-view v-else-if="card.playerKind === 'webview'" class="video-card-webview" :src="card.playerUrl" />
                  <view v-else class="video-card-inline-empty">该视频暂不支持卡片内播放，请点击下方官方页面查看。</view>
                </view>
                <view v-else class="video-card-cover-button" @tap.stop="playVideoCard(card)">
                  <view class="video-card-cover-wrap">
                    <image v-if="card.coverUrl" class="video-card-cover" :src="card.coverUrl" mode="aspectFill" />
                    <view v-else class="video-card-cover video-card-cover-empty">官方视频</view>
                    <view class="video-card-play" aria-hidden="true">▶</view>
                  </view>
                </view>
                <view class="video-card-body">
                  <view class="video-card-label">{{ card.label }}</view>
                  <view class="video-card-title">{{ card.title }}</view>
                  <view class="video-card-meta">
                    <text>{{ card.publisher || card.officialAccount || '官方发布' }}</text>
                    <text v-if="card.platform">{{ card.platform }}</text>
                    <text v-if="card.durationSeconds">{{ Math.floor(card.durationSeconds / 60) }}:{{ String(card.durationSeconds % 60).padStart(2, '0') }}</text>
                  </view>
                  <view class="video-card-action" :class="{ 'is-playing': isVideoPlaying(card) }" @tap.stop="playVideoCard(card)">{{ isVideoPlaying(card) ? '视频已在卡片内播放' : '当前页播放' }}</view>
                  <view class="video-card-official-link" @tap.stop="openOfficialVideo(card)">打开官方页面</view>
                </view>
              </view>
            </view>
          </view>
        </view>
      </template>
    </scroll-view>

    <view v-if="toolPanelOpen" class="tool-panel">
      <button class="tool-panel-item" @tap="openReportModal">
        <view class="tool-panel-title">可疑链接/内容一键举报</view>
        <view class="tool-panel-copy">粘贴短信、链接、账号或聊天记录进行研判</view>
      </button>
    </view>

    <view class="composer-shell">
      <view class="input-pill">
        <button class="icon-btn" :class="{ active: recording }" @tap="toggleRecord">
          <view class="mic-icon">
            <view class="mic-head"></view>
            <view class="mic-stem"></view>
            <view class="mic-base"></view>
          </view>
        </button>
        <button class="icon-btn" @tap="toggleToolPanel">
          <view class="plus-icon">
            <view class="plus-h"></view>
            <view class="plus-v"></view>
          </view>
        </button>
        <textarea class="chat-input" maxlength="800" auto-height placeholder="发消息" v-model="inputText" />
        <button class="send-btn" :loading="sending" :disabled="sending || !inputText" @tap="sendMessage()">发送</button>
      </view>
      <view v-if="statusText" class="status" :class="{ error }">{{ statusText }}</view>
    </view>

    <view v-if="reportModalOpen" class="report-mask" @tap="closeReportModal">
      <view class="report-sheet" @tap.stop>
        <view class="report-head">
          <view>
            <view class="report-title">可疑链接/内容一键举报</view>
            <view class="report-subtitle">先研判，再确认举报</view>
          </view>
          <button class="report-close" @tap="closeReportModal">×</button>
        </view>
        <textarea class="report-input" maxlength="1600" placeholder="粘贴可疑短信、链接、账号、App 名称或聊天记录" v-model="reportContent" />
        <view class="report-actions">
          <button class="report-secondary" @tap="clearReportTool">清空</button>
          <button class="report-primary" :loading="reportLoading" :disabled="reportLoading || !reportContent" @tap="analyzeReportTool">开始研判</button>
        </view>
        <view v-if="reportStatusText" class="report-status" :class="{ error: reportError }">{{ reportStatusText }}</view>
        <view v-if="reportAnalysis" class="report-result">
          <view class="report-result-head">
            <view>
              <view class="report-risk">{{ reportAnalysis.risk_level || '研判结果' }}</view>
              <view class="report-type">{{ reportAnalysis.suspected_type || reportAnalysis.fraud_type || '类型待确认' }}</view>
            </view>
            <view v-if="reportAnalysis.risk_score" class="report-score">{{ reportAnalysis.risk_score }}</view>
          </view>
          <view class="report-summary">{{ reportAnalysis.display_summary || reportAnalysis.answer || reportAnalysis.message }}</view>
          <view v-if="reportMatchedRules.length" class="report-list">
            <view class="report-list-title">命中规则</view>
            <view v-for="item in reportMatchedRules" :key="item" class="report-list-item">{{ item }}</view>
          </view>
          <view v-if="reportAdvice.length" class="report-list">
            <view class="report-list-title">建议</view>
            <view v-for="item in reportAdvice" :key="item" class="report-list-item">{{ item }}</view>
          </view>
          <button class="report-confirm" :loading="reportConfirming" :disabled="reportConfirming || reportConfirmed || !reportCanConfirm" @tap="confirmReportTool">
            {{ reportConfirmed ? '已确认举报' : '确认举报' }}
          </button>
        </view>
      </view>
    </view>
  </view>
</template>

<script setup>
import { computed, ref } from "vue";
import { onLoad, onShow, onUnload } from "@dcloudio/uni-app";
import { post } from "../../utils/api";
import { addRecord, scopedKey } from "../../utils/storage";
import { recorderManager, transcribeAudioFile } from "../../utils/audio";
import {
  answerFromResponse,
  cleanText,
  defaultTopInsight,
  isRiskMeta,
  responseMetaFromData,
  riskCardFromResponse,
  topInsightFromRiskCard,
  videoCardsFromResponse,
  videoPlayerInfo
} from "../../utils/risk";

const SESSION_LIMIT = 30;
const quickPrompts = [
  { text: "我正在被催转账" },
  { text: "帮我判断这是不是诈骗" },
  { text: "讲讲冒充客服骗局" }
];
const welcomeMessage = () => ({ id: "m0", role: "bot", text: "你好，我可以帮你判断诈骗风险、解释套路，并给出处置建议。" });

const navTop = ref(36);
const topbarHeight = ref(48);
const navOffset = ref(84);
const menuTop = ref(36);
const inputText = ref("");
const messages = ref([welcomeMessage()]);
const displayMessages = ref([]);
const playingVideoIds = ref(new Set());
const showWelcome = ref(true);
const lastMessageId = ref("m0");
const sessions = ref([]);
const activeSessionId = ref("");
const sessionId = ref("");
const conversationMeta = ref({});
const sending = ref(false);
const recording = ref(false);
const statusText = ref("");
const error = ref(false);
const menuOpen = ref(false);
const toolPanelOpen = ref(false);
const topInsight = ref(defaultTopInsight());
const topInsightExpanded = ref(false);
const topInsightHeightPx = ref(44);
const reportModalOpen = ref(false);
const reportContent = ref("");
const reportLoading = ref(false);
const reportConfirming = ref(false);
const reportConfirmed = ref(false);
const reportStatusText = ref("");
const reportError = ref(false);
const reportAnalysis = ref(null);
const reportMatchedRules = ref([]);
const reportAdvice = ref([]);
const reportCanConfirm = ref(false);
let recorder = null;
let recordingStarted = false;

const menuStyle = computed(() => `margin-top:${menuTop.value}px;height:calc(100vh - ${menuTop.value}px);`);
const messagesStyle = computed(() => `height:calc(100vh - ${navOffset.value}px - ${topInsightHeightPx.value}px - 71px - env(safe-area-inset-bottom));`);

function setupNavigation() {
  try {
    const info = uni.getSystemInfoSync();
    const statusBarHeight = Number(info.statusBarHeight || 24);
    navTop.value = statusBarHeight + 12;
    topbarHeight.value = 48;
    navOffset.value = navTop.value + topbarHeight.value;
    menuTop.value = navTop.value;
  } catch (err) {
    navTop.value = 36;
    topbarHeight.value = 48;
    navOffset.value = 84;
    menuTop.value = 36;
  }
}

function stripDefaultWelcome(items) {
  return (Array.isArray(items) ? items : []).filter((item) => !(item && item.id === "m0" && item.role === "bot"));
}

function applyChatView(items) {
  const display = stripDefaultWelcome(items);
  const last = display[display.length - 1] || items[items.length - 1] || welcomeMessage();
  displayMessages.value = display;
  showWelcome.value = display.length === 0;
  lastMessageId.value = last.id || "m0";
}

function titleFromMessages(items) {
  const firstUser = (items || []).find((item) => item.role === "user" && cleanText(item.text));
  const text = firstUser ? cleanText(firstUser.text) : "新对话";
  return text.length > 18 ? `${text.slice(0, 18)}...` : text;
}

function sessionStoreKey() {
  return scopedKey("chatSessions");
}

function activeStoreKey() {
  return scopedKey("activeChatSession");
}

function readSessions() {
  const value = uni.getStorageSync(sessionStoreKey());
  return Array.isArray(value) ? value : [];
}

function writeSessions(items) {
  uni.setStorageSync(sessionStoreKey(), items.slice(0, SESSION_LIMIT));
}

function blankSession() {
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
}

function setTopInsight(nextInsight, expanded = false) {
  topInsight.value = nextInsight || defaultTopInsight();
  topInsightExpanded.value = Boolean(expanded && topInsight.value.hasDetails);
  topInsightHeightPx.value = topInsightExpanded.value ? 162 : 44;
}

function topInsightFromMessages(items, meta = {}) {
  const source = stripDefaultWelcome(items);
  for (let index = source.length - 1; index >= 0; index -= 1) {
    const item = source[index];
    if (item && item.role === "bot" && (item.riskCard || isRiskMeta(item.meta))) {
      return topInsightFromRiskCard(item.riskCard, item.meta);
    }
  }
  return isRiskMeta(meta) ? topInsightFromRiskCard(null, meta) : defaultTopInsight();
}

function loadSessions() {
  let items = readSessions();
  if (!items.length) items = [blankSession()];
  const activeId = uni.getStorageSync(activeStoreKey()) || items[0].id;
  const active = items.find((item) => item.id === activeId) || items[0];
  const activeMessages = active.messages && active.messages.length ? active.messages : [welcomeMessage()];
  writeSessions(items);
  uni.setStorageSync(activeStoreKey(), active.id);
  sessions.value = items;
  activeSessionId.value = active.id;
  sessionId.value = active.sessionId || "";
  conversationMeta.value = active.meta || {};
  messages.value = activeMessages;
  applyChatView(activeMessages);
  setTopInsight(topInsightFromMessages(activeMessages, active.meta || {}), false);
}

function persistCurrent(extra = {}) {
  const now = new Date().toISOString();
  const nextMessages = extra.messages || messages.value;
  const others = readSessions().filter((item) => item.id !== activeSessionId.value);
  const old = readSessions().find((item) => item.id === activeSessionId.value) || {};
  const current = {
    id: activeSessionId.value || blankSession().id,
    sessionId: extra.sessionId !== undefined ? extra.sessionId : sessionId.value,
    title: titleFromMessages(nextMessages),
    createdAt: old.createdAt || now,
    updatedAt: now,
    messages: nextMessages,
    meta: extra.meta !== undefined ? extra.meta : conversationMeta.value
  };
  const next = [current].concat(others).slice(0, SESSION_LIMIT);
  writeSessions(next);
  uni.setStorageSync(activeStoreKey(), current.id);
  sessions.value = next;
  activeSessionId.value = current.id;
}

function newMessage(role, text, extra = {}) {
  return {
    id: `m${Date.now()}-${Math.random().toString(16).slice(2, 7)}`,
    role,
    text,
    ...extra
  };
}

function compactText(value) {
  return cleanText(value).replace(/\s+/g, "");
}

function buildChatHistory(items, meta) {
  const source = stripDefaultWelcome(items);
  if (isRiskMeta(meta)) {
    return source
      .filter((item) => (item.role === "user" || item.role === "bot") && cleanText(item.text))
      .slice(-13)
      .slice(0, -1)
      .map((item) => ({ role: item.role === "bot" ? "assistant" : "user", content: item.text || "" }));
  }
  const current = source[source.length - 1] || {};
  const text = compactText(current.text);
  const followupMarkers = ["那", "这个", "这种", "刚才", "上面", "前面", "它", "继续", "还有", "怎么防", "如何防", "案例", "法律", "总结", "套路"];
  const standaloneMarkers = ["什么是", "是什么", "介绍", "科普", "讲讲", "我最近", "我看到", "我想咨询", "咨询一件事", "可以买吗", "能买吗", "靠谱吗", "靠不靠谱"];
  const shouldSendHistory = !standaloneMarkers.some((item) => text.includes(item)) && (text.length <= 8 || followupMarkers.some((item) => text.includes(item)));
  if (!shouldSendHistory) return [];
  return source
    .filter((item) => item.role === "user" || item.role === "bot")
    .slice(-4)
    .slice(0, -1)
    .map((item) => ({ role: item.role === "bot" ? "assistant" : "user", content: item.text || "" }));
}

function useQuickPrompt(text) {
  inputText.value = text;
}

function videoCardKey(card) {
  return cleanText(card && (card.videoId || card.sourceUrl));
}

function isVideoPlaying(card) {
  const key = videoCardKey(card);
  return Boolean(key && playingVideoIds.value.has(key));
}

function playVideoCard(card) {
  const player = videoPlayerInfo(card && card.sourceUrl, card || {});
  if (!player.url) {
    openOfficialVideo(card);
    return;
  }
  if (card && !card.playerUrl) {
    card.playerKind = player.kind;
    card.playerUrl = player.url;
  }
  const key = videoCardKey(card);
  if (!key) return;
  const next = new Set(playingVideoIds.value);
  next.add(key);
  playingVideoIds.value = next;
}

function openOfficialVideo(card) {
  const sourceUrl = cleanText(card && card.sourceUrl);
  if (!/^https?:\/\//i.test(sourceUrl)) {
    uni.showToast({ title: "官方链接暂不可用", icon: "none" });
    return;
  }
  uni.navigateTo({
    url: `/pages/video-webview/video-webview?url=${encodeURIComponent(sourceUrl)}`
  });
}

function openMenu() {
  menuOpen.value = true;
  toolPanelOpen.value = false;
}

function closeMenu() {
  menuOpen.value = false;
}

function goTraining() {
  closeMenu();
  uni.navigateTo({ url: "/pages/training/training" });
}

function goSimulation() {
  closeMenu();
  uni.navigateTo({ url: "/pages/simulation/simulation" });
}

function toggleToolPanel() {
  toolPanelOpen.value = !toolPanelOpen.value;
  menuOpen.value = false;
}

function newChat() {
  if (!stripDefaultWelcome(messages.value).length) {
    menuOpen.value = false;
    toolPanelOpen.value = false;
    uni.showToast({ title: "目前已经在新对话了", icon: "none", duration: 1400 });
    return;
  }
  const session = blankSession();
  const next = [session].concat(readSessions()).slice(0, SESSION_LIMIT);
  writeSessions(next);
  uni.setStorageSync(activeStoreKey(), session.id);
  sessions.value = next;
  activeSessionId.value = session.id;
  sessionId.value = "";
  conversationMeta.value = {};
  playingVideoIds.value = new Set();
  inputText.value = "";
  messages.value = session.messages;
  applyChatView(session.messages);
  setTopInsight(defaultTopInsight(), false);
}

function openSession(id) {
  const session = readSessions().find((item) => item.id === id);
  if (!session) return;
  const nextMessages = session.messages && session.messages.length ? session.messages : [welcomeMessage()];
  uni.setStorageSync(activeStoreKey(), id);
  inputText.value = "";
  messages.value = nextMessages;
  sessions.value = readSessions();
  activeSessionId.value = id;
  sessionId.value = session.sessionId || "";
  conversationMeta.value = session.meta || {};
  playingVideoIds.value = new Set();
  menuOpen.value = false;
  toolPanelOpen.value = false;
  statusText.value = "";
  error.value = false;
  applyChatView(nextMessages);
  setTopInsight(topInsightFromMessages(nextMessages, session.meta || {}), false);
}

async function sendMessage(textOverride = "", options = {}) {
  const providedText = typeof textOverride === "string" ? textOverride : "";
  const text = cleanText(providedText || inputText.value);
  if (!text || sending.value) return;
  const existingMessages = stripDefaultWelcome(messages.value);
  const userMessage = newMessage("user", text, { inputMode: options.inputMode || "text" });
  const nextMessages = existingMessages.concat(userMessage);
  messages.value = nextMessages;
  inputText.value = "";
  sending.value = true;
  statusText.value = options.inputMode === "voice" ? "语音已转文字，正在研判" : "正在研判";
  error.value = false;
  applyChatView(nextMessages);
  persistCurrent({ messages: nextMessages });
  try {
    const data = await post("/knowledge/chat", {
      message: text,
      session_id: sessionId.value || undefined,
      history: buildChatHistory(nextMessages, conversationMeta.value),
      use_llm: true,
      limit: 8,
      is_stream: false,
      input_mode: options.inputMode || "text"
    });
    const responseMeta = responseMetaFromData(data);
    const riskCard = riskCardFromResponse(data);
    const botMessage = newMessage("bot", answerFromResponse(data), {
      meta: responseMeta,
      riskCard,
      videoCards: videoCardsFromResponse(data)
    });
    const finalMessages = nextMessages.concat(botMessage);
    messages.value = finalMessages;
    sessionId.value = data.session_id || sessionId.value;
    conversationMeta.value = responseMeta;
    statusText.value = "";
    error.value = false;
    applyChatView(finalMessages);
    setTopInsight(topInsightFromRiskCard(riskCard, responseMeta), false);
    persistCurrent({ messages: finalMessages, sessionId: sessionId.value, meta: responseMeta });
    addRecord("learningRecords", {
      type: options.inputMode === "voice" ? "语音咨询" : "反诈咨询",
      title: titleFromMessages(finalMessages),
      content: text,
      result: botMessage.text
    });
  } catch (err) {
    const botMessage = newMessage("bot", `请求失败：${err.message}`);
    const finalMessages = nextMessages.concat(botMessage);
    messages.value = finalMessages;
    statusText.value = err.message;
    error.value = true;
    applyChatView(finalMessages);
    persistCurrent({ messages: finalMessages });
  } finally {
    sending.value = false;
  }
}

function toggleTopInsight() {
  if (!topInsight.value.hasDetails) return;
  topInsightExpanded.value = !topInsightExpanded.value;
  topInsightHeightPx.value = topInsightExpanded.value ? 162 : 44;
}

function reportAnalysisId(analysis) {
  return cleanText(analysis && (analysis.analysis_id || analysis.id || (analysis.report_intel && analysis.report_intel.analysis_id)));
}

function openReportModal() {
  toolPanelOpen.value = false;
  reportModalOpen.value = true;
  reportStatusText.value = "";
  reportError.value = false;
}

function closeReportModal() {
  if (reportLoading.value || reportConfirming.value) return;
  reportModalOpen.value = false;
}

function clearReportTool() {
  if (reportLoading.value || reportConfirming.value) return;
  reportContent.value = "";
  reportStatusText.value = "";
  reportError.value = false;
  reportAnalysis.value = null;
  reportMatchedRules.value = [];
  reportAdvice.value = [];
  reportCanConfirm.value = false;
  reportConfirmed.value = false;
}

function asTextList(value) {
  if (Array.isArray(value)) return value.filter(Boolean).map(String);
  if (!value) return [];
  return [String(value)];
}

async function analyzeReportTool() {
  const content = cleanText(reportContent.value);
  if (!content || reportLoading.value) return;
  reportLoading.value = true;
  reportStatusText.value = "正在研判";
  reportError.value = false;
  reportConfirmed.value = false;
  try {
    const analysis = await post("/report-intel/analyze", { content });
    reportAnalysis.value = analysis;
    reportMatchedRules.value = asTextList(analysis.matched_rules);
    reportAdvice.value = asTextList(analysis.advice);
    reportCanConfirm.value = Boolean(reportAnalysisId(analysis));
    reportStatusText.value = analysis.message || "研判完成";
    addRecord("reportRecords", {
      type: "举报研判",
      title: analysis.suspected_type || analysis.fraud_type || analysis.risk_level || "研判结果",
      content,
      result: analysis.display_summary || analysis.answer || analysis.message || ""
    });
  } catch (err) {
    reportStatusText.value = err.message;
    reportError.value = true;
  } finally {
    reportLoading.value = false;
  }
}

async function confirmReportTool() {
  const analysisId = reportAnalysisId(reportAnalysis.value);
  if (!analysisId || reportConfirming.value) return;
  reportConfirming.value = true;
  reportStatusText.value = "正在确认举报";
  reportError.value = false;
  try {
    const data = await post("/report-intel/confirm", {
      analysis_id: analysisId,
      reporter_note: "来自移动 App 聊天页确认"
    });
    reportConfirmed.value = true;
    reportStatusText.value = data.report_id ? `举报已确认：${data.report_id}` : data.message || "举报已确认";
    addRecord("reportRecords", {
      type: "确认举报",
      title: data.report_id || "举报已确认",
      content: reportContent.value,
      result: data.message || "举报已确认"
    });
  } catch (err) {
    reportStatusText.value = err.message;
    reportError.value = true;
  } finally {
    reportConfirming.value = false;
  }
}

function toggleRecord() {
  if (!recorder) {
    uni.showToast({ title: "当前平台暂不支持录音", icon: "none" });
    return;
  }
  if (recording.value) {
    recorder.stop();
    return;
  }
  recordingStarted = true;
  recording.value = true;
  statusText.value = "正在录音，说完后点停止";
  error.value = false;
  recorder.start({
    duration: 15000,
    sampleRate: 16000,
    numberOfChannels: 1,
    encodeBitRate: 64000,
    format: "wav"
  });
}

onLoad(() => {
  setupNavigation();
  recorder = recorderManager();
  if (recorder) {
    recorder.onStop(async (res) => {
      if (!recordingStarted) return;
      recordingStarted = false;
      recording.value = false;
      statusText.value = "正在识别语音";
      try {
        const asr = await transcribeAudioFile(res.tempFilePath, { audioFormat: "wav", sampleRate: 16000 });
        const text = cleanText(asr.text);
        if (!text) {
          statusText.value = "没有听清，请说一句完整的话";
          return;
        }
        inputText.value = text;
        await sendMessage(text, { inputMode: "voice" });
      } catch (err) {
        statusText.value = err.message;
        error.value = true;
      }
    });
    recorder.onError((err) => {
      recordingStarted = false;
      recording.value = false;
      statusText.value = err.errMsg || "录音失败";
      error.value = true;
    });
  }
  loadSessions();
});

onShow(() => {
  if (!activeSessionId.value) loadSessions();
});

onUnload(() => {
  if (recording.value && recorder) {
    try {
      recorder.stop();
    } catch (err) {
      recordingStarted = false;
    }
  }
});
</script>

<style scoped>
.screen {
  min-height: 100vh;
  background: #fff;
  color: #151515;
  padding-left: 24rpx;
  padding-right: 24rpx;
  padding-bottom: calc(152rpx + env(safe-area-inset-bottom));
  box-sizing: border-box;
}

.topbar {
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
}

.top-action {
  position: absolute;
  top: 50%;
  width: 64rpx;
  height: 64rpx;
  border: 0;
  border-radius: 50%;
  background: #fff;
  color: #161616;
  font-size: 34rpx;
  line-height: 64rpx;
  padding: 0;
  transform: translateY(-50%);
}

.menu-action {
  left: 0;
  letter-spacing: 2rpx;
}

.new-action {
  right: 0;
  font-size: 38rpx;
}

.top-title {
  color: #111;
  font-size: 30rpx;
  font-weight: 650;
}

.top-insight {
  height: 76rpx;
  margin-bottom: 12rpx;
  border: 1rpx solid #eee;
  border-radius: 20rpx;
  background: #fafafa;
  padding: 0 18rpx;
  box-sizing: border-box;
  overflow: hidden;
}

.top-insight.expanded {
  height: 312rpx;
  padding: 18rpx;
  overflow-y: auto;
}

.top-insight.risk {
  background: #f8f8f8;
}

.top-insight-row {
  min-height: 74rpx;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16rpx;
}

.top-insight.expanded .top-insight-row {
  min-height: 42rpx;
}

.top-insight-title {
  flex: 1;
  color: #111;
  font-size: 27rpx;
  font-weight: 650;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.top-insight-badge {
  flex-shrink: 0;
  border-radius: 999rpx;
  background: #111;
  color: #fff;
  padding: 7rpx 16rpx;
  font-size: 21rpx;
}

.top-insight.knowledge .top-insight-badge {
  background: #eee;
  color: #333;
}

.top-insight-detail {
  border-top: 1rpx solid #e9e9e9;
  margin-top: 12rpx;
  padding-top: 14rpx;
}

.top-insight-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 10rpx;
}

.top-insight-cell {
  width: calc(50% - 5rpx);
  border-radius: 14rpx;
  background: #fff;
  padding: 12rpx 14rpx;
  box-sizing: border-box;
}

.top-insight-cell text,
.top-insight-list-title {
  display: block;
  color: #8a8a8a;
  font-size: 21rpx;
}

.top-insight-cell strong {
  display: block;
  margin-top: 6rpx;
  color: #202020;
  font-size: 24rpx;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.top-insight-summary,
.top-insight-item {
  color: #333;
  font-size: 24rpx;
  line-height: 1.5;
}

.top-insight-summary,
.top-insight-list {
  margin-top: 14rpx;
}

.menu-mask {
  position: fixed;
  inset: 0;
  z-index: 80;
  background: rgba(0, 0, 0, 0.16);
}

.side-menu {
  width: 590rpx;
  max-width: 82vw;
  background: #fff;
  box-shadow: 16rpx 0 44rpx rgba(0, 0, 0, 0.12);
  padding: 34rpx 28rpx calc(34rpx + env(safe-area-inset-bottom));
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
}

.menu-section {
  border-bottom: 1rpx solid #eee;
  padding-bottom: 14rpx;
}

.menu-item {
  min-height: 104rpx;
  display: flex;
  align-items: center;
  gap: 18rpx;
}

.menu-dot {
  width: 58rpx;
  height: 58rpx;
  border-radius: 50%;
  background: #f3f3f3;
  color: #222;
  font-size: 24rpx;
  line-height: 58rpx;
  text-align: center;
}

.menu-copy {
  flex: 1;
  min-width: 0;
}

.menu-title {
  color: #141414;
  font-size: 29rpx;
  font-weight: 650;
}

.menu-subtitle,
.history-meta {
  margin-top: 8rpx;
  color: #8a8a8a;
  font-size: 24rpx;
}

.history-head {
  margin-top: 28rpx;
  color: #8a8a8a;
  font-size: 24rpx;
}

.history-list {
  flex: 1;
  min-height: 0;
  margin-top: 12rpx;
}

.history-row {
  min-height: 86rpx;
  border-bottom: 1rpx solid #f1f1f1;
  padding: 16rpx 4rpx;
  box-sizing: border-box;
}

.history-row.active {
  background: #f7f7f7;
  border-radius: 16rpx;
  padding-left: 16rpx;
  padding-right: 16rpx;
  border-bottom-color: transparent;
}

.history-title {
  color: #151515;
  font-size: 27rpx;
  font-weight: 550;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.messages {
  box-sizing: border-box;
  padding: 16rpx 0 30rpx;
}

.messages.is-empty {
  display: flex;
  align-items: center;
}

.welcome-panel {
  width: 100%;
  padding: 8rpx 18rpx 80rpx;
  box-sizing: border-box;
  text-align: center;
}

.welcome-mark {
  width: 76rpx;
  height: 76rpx;
  border-radius: 50%;
  background: #111;
  margin: 0 auto 32rpx;
}

.welcome-title {
  color: #111;
  font-size: 44rpx;
  font-weight: 650;
}

.welcome-copy {
  width: 88%;
  margin: 20rpx auto 0;
  color: #747474;
  font-size: 27rpx;
  line-height: 1.65;
}

.welcome-prompts {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 14rpx;
  margin-top: 32rpx;
}

.welcome-chip {
  min-height: 60rpx;
  border: 1rpx solid #ececec;
  border-radius: 999rpx;
  background: #fff;
  color: #333;
  padding: 0 22rpx;
  font-size: 24rpx;
  line-height: 60rpx;
}

.message {
  display: flex;
  margin-bottom: 26rpx;
}

.message.user {
  justify-content: flex-end;
}

.bubble-wrap {
  max-width: 92%;
}

.message.user .bubble-wrap {
  max-width: 82%;
}

.bubble {
  color: #151515;
  font-size: 30rpx;
  line-height: 1.72;
  white-space: pre-wrap;
  word-break: break-word;
}

.message.user .bubble {
  border-radius: 26rpx;
  background: #f1f1f1;
  padding: 18rpx 24rpx;
}

.video-card-list {
  display: grid;
  gap: 16rpx;
  margin-top: 18rpx;
}

.video-card {
  width: min(620rpx, 100%);
  overflow: hidden;
  border: 1rpx solid #dfe7e5;
  border-radius: 16rpx;
  background: #ffffff;
  box-shadow: 0 8rpx 24rpx rgba(28, 55, 51, 0.08);
}

.video-card-cover-wrap {
  position: relative;
  width: 100%;
  height: 230rpx;
  background: #e7f3f0;
}

.video-card-cover-button {
  display: block;
  width: 100%;
}

.video-card-inline-player {
  width: 100%;
  height: 230rpx;
  overflow: hidden;
  background: #000;
}

.video-card-video,
.video-card-webview {
  display: block;
  width: 100%;
  height: 100%;
}

.video-card-inline-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  padding: 24rpx;
  box-sizing: border-box;
  color: #1d5f5b;
  background: #e7f3f0;
  font-size: 24rpx;
  line-height: 1.6;
  text-align: center;
}

.video-card-cover {
  display: block;
  width: 100%;
  height: 100%;
}

.video-card-cover-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  color: #1d5f5b;
  font-size: 28rpx;
  font-weight: 650;
}

.video-card-play {
  position: absolute;
  left: 50%;
  top: 50%;
  width: 64rpx;
  height: 64rpx;
  border-radius: 50%;
  background: rgba(17, 17, 17, 0.72);
  color: #ffffff;
  font-size: 26rpx;
  line-height: 64rpx;
  text-align: center;
  transform: translate(-50%, -50%);
}

.video-card-body {
  padding: 18rpx 20rpx 20rpx;
}

.video-card-label {
  color: #1d5f5b;
  font-size: 22rpx;
  font-weight: 650;
}

.video-card-title {
  margin-top: 8rpx;
  color: #151515;
  font-size: 28rpx;
  font-weight: 650;
  line-height: 1.4;
  word-break: break-word;
}

.video-card-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8rpx 18rpx;
  margin-top: 10rpx;
  color: #777777;
  font-size: 22rpx;
  line-height: 1.4;
}

.video-card-action {
  margin-top: 14rpx;
  color: #116d7a;
  font-size: 24rpx;
  font-weight: 650;
}

.video-card-action.is-playing {
  color: #777;
  text-decoration: none;
}

.video-card-official-link {
  margin-top: 10rpx;
  color: #116d7a;
  font-size: 24rpx;
  font-weight: 650;
  text-decoration: underline;
  text-underline-offset: 2rpx;
}

.tool-panel {
  position: fixed;
  left: 24rpx;
  right: 24rpx;
  bottom: calc(132rpx + env(safe-area-inset-bottom));
  z-index: 30;
  border: 1rpx solid #e8e8e8;
  border-radius: 24rpx;
  background: #fff;
  box-shadow: 0 12rpx 34rpx rgba(0, 0, 0, 0.08);
  padding: 12rpx;
  box-sizing: border-box;
}

.tool-panel-item {
  width: 100%;
  border: 0;
  border-radius: 18rpx;
  background: #f7f7f7;
  padding: 22rpx;
  box-sizing: border-box;
  text-align: left;
}

.tool-panel-title {
  color: #151515;
  font-size: 28rpx;
  font-weight: 650;
}

.tool-panel-copy {
  margin-top: 8rpx;
  color: #777;
  font-size: 24rpx;
}

.composer-shell {
  position: fixed;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 20;
  background: rgba(255, 255, 255, 0.98);
  padding: 16rpx 24rpx calc(18rpx + env(safe-area-inset-bottom));
  box-sizing: border-box;
  border-top: 1rpx solid #eee;
}

.input-pill {
  min-height: 88rpx;
  border: 1rpx solid #e4e4e4;
  border-radius: 30rpx;
  background: #f7f7f7;
  display: flex;
  align-items: center;
  gap: 10rpx;
  padding: 12rpx 12rpx 12rpx 14rpx;
  box-sizing: border-box;
}

.icon-btn {
  width: 62rpx;
  height: 62rpx;
  border: 0;
  border-radius: 50%;
  background: transparent;
  padding: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.icon-btn.active {
  background: #eee;
}

.mic-icon {
  width: 32rpx;
  height: 42rpx;
}

.mic-head {
  width: 20rpx;
  height: 27rpx;
  border: 3rpx solid #111;
  border-radius: 14rpx;
  margin: 0 auto;
  box-sizing: border-box;
}

.mic-stem {
  width: 3rpx;
  height: 12rpx;
  background: #111;
  margin: 0 auto;
}

.mic-base {
  width: 24rpx;
  height: 3rpx;
  border-radius: 999rpx;
  background: #111;
  margin: 0 auto;
}

.plus-icon {
  width: 28rpx;
  height: 28rpx;
  position: relative;
}

.plus-h,
.plus-v {
  position: absolute;
  left: 50%;
  top: 50%;
  border-radius: 999rpx;
  background: #111;
  transform: translate(-50%, -50%);
}

.plus-h {
  width: 28rpx;
  height: 3rpx;
}

.plus-v {
  width: 3rpx;
  height: 28rpx;
}

.chat-input {
  height: 58rpx;
  min-height: 58rpx;
  max-height: 168rpx;
  flex: 1;
  color: #141414;
  font-size: 29rpx;
  line-height: 42rpx;
  padding: 8rpx 0;
  box-sizing: border-box;
  overflow-y: auto;
}

.send-btn {
  min-width: 88rpx;
  min-height: 62rpx;
  border-radius: 999rpx;
  background: #111;
  color: #fff;
  padding: 0 18rpx;
  font-size: 25rpx;
  line-height: 62rpx;
}

.send-btn[disabled] {
  background: #d4d4d4;
}

.status {
  margin-top: 10rpx;
  color: #777;
  font-size: 24rpx;
}

.status.error,
.report-status.error {
  color: #a23a3a;
}

.report-mask {
  position: fixed;
  inset: 0;
  z-index: 100;
  background: rgba(0, 0, 0, 0.22);
  display: flex;
  align-items: flex-end;
}

.report-sheet {
  width: 100%;
  max-height: 86vh;
  overflow: hidden;
  border-radius: 30rpx 30rpx 0 0;
  background: #fff;
  padding: 28rpx 28rpx calc(28rpx + env(safe-area-inset-bottom));
  box-sizing: border-box;
}

.report-head,
.report-result-head,
.report-actions {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18rpx;
}

.report-title,
.report-risk {
  color: #111;
  font-size: 31rpx;
  font-weight: 650;
}

.report-subtitle,
.report-type,
.report-status {
  margin-top: 8rpx;
  color: #888;
  font-size: 24rpx;
}

.report-close {
  width: 60rpx;
  height: 60rpx;
  border: 0;
  border-radius: 50%;
  background: #f3f3f3;
  color: #111;
  font-size: 34rpx;
  line-height: 60rpx;
  padding: 0;
}

.report-input {
  width: 100%;
  min-height: 190rpx;
  max-height: 260rpx;
  border: 1rpx solid #e5e5e5;
  border-radius: 22rpx;
  background: #f8f8f8;
  margin-top: 24rpx;
  padding: 20rpx;
  box-sizing: border-box;
  color: #151515;
  font-size: 28rpx;
  line-height: 1.55;
}

.report-actions {
  margin-top: 18rpx;
}

.report-secondary,
.report-primary,
.report-confirm {
  min-height: 74rpx;
  border-radius: 999rpx;
  font-size: 27rpx;
  line-height: 74rpx;
}

.report-secondary {
  flex: 1;
  background: #f3f3f3;
  color: #222;
}

.report-primary {
  flex: 2;
  background: #111;
  color: #fff;
}

.report-result {
  max-height: 42vh;
  overflow-y: auto;
  border: 1rpx solid #eee;
  border-radius: 22rpx;
  background: #fafafa;
  margin-top: 20rpx;
  padding: 20rpx;
  box-sizing: border-box;
}

.report-score {
  min-width: 64rpx;
  height: 64rpx;
  border-radius: 50%;
  background: #111;
  color: #fff;
  font-size: 26rpx;
  line-height: 64rpx;
  text-align: center;
}

.report-summary,
.report-list-item {
  margin-top: 18rpx;
  color: #303030;
  font-size: 26rpx;
  line-height: 1.6;
  white-space: pre-wrap;
}

.report-list-title {
  margin-top: 18rpx;
  color: #888;
  font-size: 23rpx;
}

.report-confirm {
  width: 100%;
  background: #111;
  color: #fff;
  margin-top: 20rpx;
}

.report-confirm[disabled] {
  background: #d4d4d4;
}
</style>
