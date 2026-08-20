<template>
  <view class="page" :style="{ paddingTop: navTop + 'px' }">
    <view class="nav">
      <button class="back" @tap="goBack">‹</button>
      <view class="nav-title">骗局模拟</view>
    </view>

    <view class="section">
      <view class="title">实时骗局模拟</view>
      <view class="subtitle">和模拟骗子对练。明确拒绝、官方核实、保留证据才能拿高分。</view>
    </view>

    <view v-if="!sessionId" class="surface section">
      <view class="label">难度</view>
      <picker mode="selector" :range="difficultyLabels" :value="difficultyIndex" @change="onDifficultyChange">
        <view class="picker">{{ difficultyLabels[difficultyIndex] }}</view>
      </picker>
      <view class="button-row">
        <button class="primary-btn" :loading="loading" :disabled="loading" @tap="startSimulation">开始模拟</button>
      </view>
    </view>

    <view v-if="simulation" class="surface scenario">
      <view class="scenario-head">
        <view>
          <view class="scenario-title">{{ simulation.fraud_type || '典型骗局' }}</view>
          <view class="scenario-subtitle">{{ simulation.difficulty_label || '中等模式' }} · {{ simulation.turn_count || 0 }}/{{ simulation.max_turns || 0 }} 轮</view>
        </view>
        <view class="pill">自称：{{ simulation.scammer_identity || '平台工作人员' }}</view>
      </view>
      <view v-if="riskText" class="risk-list">风险信号：{{ riskText }}</view>
    </view>

    <scroll-view v-if="sessionId" class="messages surface" scroll-y :scroll-into-view="lastMessageId">
      <view v-for="item in messages" :id="item.id" :key="item.id" class="msg" :class="item.role">
        <view class="msg-role">{{ item.roleLabel }}</view>
        <view class="msg-bubble">{{ item.content }}</view>
      </view>
      <view v-if="result" class="final-card">
        <view class="final-title">{{ result.outcome }}</view>
        <view>得分：{{ result.score }}</view>
        <view v-if="result.debrief">{{ result.debrief }}</view>
      </view>
    </scroll-view>

    <view v-if="sessionId && !finished" class="surface composer">
      <textarea class="textarea" maxlength="500" auto-height placeholder="输入你的回应，例如：我不转账，我要去官方渠道核实。" v-model="inputText" />
      <view class="button-row">
        <button class="ghost-btn" @tap="finishSimulation">结束</button>
        <button class="primary-btn" :loading="loading" :disabled="loading || !inputText" @tap="sendTurn">发送</button>
      </view>
    </view>

    <view v-if="finished" class="button-row">
      <button class="primary-btn" @tap="resetSimulation">再来一局</button>
    </view>

    <view v-if="statusText" class="status" :class="{ error }">{{ statusText }}</view>
  </view>
</template>

<script setup>
import { ref } from "vue";
import { onLoad } from "@dcloudio/uni-app";
import { post } from "../../utils/api";
import { addRecord, currentUserId } from "../../utils/storage";

const difficulties = [
  { value: "easy", label: "简单模式" },
  { value: "medium", label: "中等模式" },
  { value: "hard", label: "困难模式" }
];
const badScammerLabels = ["冒充客服", "可疑联系人", "骗子", "诈骗分子", "诈骗人员", "冒充公检法人员"];
const navTop = ref(36);
const difficultyLabels = difficulties.map((item) => item.label);
const difficultyIndex = ref(1);
const sessionId = ref("");
const simulation = ref(null);
const messages = ref([]);
const riskText = ref("");
const inputText = ref("");
const loading = ref(false);
const statusText = ref("");
const error = ref(false);
const result = ref(null);
const finished = ref(false);
const lastMessageId = ref("");

function setupNavigation() {
  try {
    navTop.value = Number(uni.getSystemInfoSync().statusBarHeight || 24) + 12;
  } catch (err) {
    navTop.value = 36;
  }
}

function goBack() {
  uni.navigateBack({ fail: () => uni.redirectTo({ url: "/pages/chat/chat" }) });
}

function onDifficultyChange(event) {
  difficultyIndex.value = Number(event.detail.value || 0);
}

function inferScammerIdentity(nextSimulation) {
  const explicit = String((nextSimulation && nextSimulation.scammer_identity) || "").trim();
  if (explicit && !badScammerLabels.includes(explicit)) return explicit;
  const text = [nextSimulation && nextSimulation.fraud_type, nextSimulation && nextSimulation.scammer_role, nextSimulation && nextSimulation.scenario].join(" ");
  if (text.includes("游戏交易") || text.includes("账号交易")) return "交易平台客服";
  if (text.includes("刷单") || text.includes("返利")) return "任务派单客服";
  if (text.includes("客服") || text.includes("退款") || text.includes("理赔")) return "平台客服";
  if (text.includes("公检法") || text.includes("民警") || text.includes("公安")) return "公安机关工作人员";
  if (text.includes("贷款")) return "贷款客服";
  if (text.includes("中奖") || text.includes("礼品")) return "活动客服";
  if (text.includes("招聘")) return "招聘专员";
  return "平台工作人员";
}

function sanitizeScammerText(text, identity) {
  let value = String(text || "");
  badScammerLabels.forEach((label) => {
    value = value
      .replace(new RegExp(`我是${label}`, "g"), `我是${identity}`)
      .replace(new RegExp(`我是一名${label}`, "g"), `我是一名${identity}`)
      .replace(new RegExp(`我是一个${label}`, "g"), `我是一个${identity}`);
  });
  return value;
}

function messageItems(nextSimulation) {
  const identity = inferScammerIdentity(nextSimulation);
  return (nextSimulation && nextSimulation.messages ? nextSimulation.messages : []).map((item, index) => ({
    id: `msg-${index}`,
    role: item.role,
    roleLabel: item.role === "scammer" ? "对方" : "我",
    content: item.role === "scammer" ? sanitizeScammerText(item.content || item.text || "", identity) : (item.content || item.text || "")
  }));
}

function applySimulation(nextSimulation, extra = {}) {
  const identity = inferScammerIdentity(nextSimulation);
  const normalized = { ...nextSimulation, scammer_identity: identity };
  const nextMessages = messageItems(normalized);
  simulation.value = normalized;
  sessionId.value = normalized.session_id || sessionId.value;
  messages.value = nextMessages;
  riskText.value = (normalized.risk_signals || []).join("、");
  lastMessageId.value = nextMessages.length ? nextMessages[nextMessages.length - 1].id : "";
  Object.keys(extra).forEach((key) => {
    if (key === "inputText") inputText.value = extra[key];
    if (key === "result") result.value = extra[key];
    if (key === "finished") finished.value = extra[key];
    if (key === "statusText") statusText.value = extra[key];
  });
}

async function startSimulation() {
  loading.value = true;
  statusText.value = "正在启动模拟";
  error.value = false;
  result.value = null;
  finished.value = false;
  try {
    const data = await post("/game/simulation/start", {
      user_id: currentUserId(),
      difficulty: difficulties[difficultyIndex.value].value,
      use_llm: true
    });
    applySimulation(data.simulation, { statusText: "模拟已开始" });
  } catch (err) {
    statusText.value = err.message;
    error.value = true;
  } finally {
    loading.value = false;
  }
}

async function sendTurn() {
  const text = String(inputText.value || "").trim();
  if (!text || loading.value) return;
  loading.value = true;
  statusText.value = "正在生成回应";
  error.value = false;
  try {
    const data = await post("/game/simulation/turn", {
      session_id: sessionId.value,
      user_message: text,
      voice_text: "",
      use_llm: true
    });
    const done = Boolean(data.result || data.outcome || (data.simulation && data.simulation.status === "finished"));
    applySimulation(data.simulation, {
      inputText: "",
      result: data.result || (done ? { score: data.score, outcome: data.outcome, debrief: data.message } : null),
      finished: done,
      statusText: data.message || ""
    });
    if (done) {
      addRecord("learningRecords", {
        type: "骗局模拟",
        title: data.outcome || (data.result && data.result.outcome) || "模拟结束",
        content: (data.simulation && data.simulation.fraud_type) || "实时骗局模拟",
        result: (data.result && data.result.debrief) || data.message || ""
      });
    }
  } catch (err) {
    statusText.value = err.message;
    error.value = true;
  } finally {
    loading.value = false;
  }
}

async function finishSimulation() {
  if (!sessionId.value || loading.value) return;
  loading.value = true;
  statusText.value = "正在评分";
  error.value = false;
  try {
    const data = await post("/game/simulation/finish", {
      session_id: sessionId.value,
      user_message: inputText.value || undefined
    });
    applySimulation(data.simulation, {
      inputText: "",
      result: data.result || { score: data.score, outcome: data.outcome, debrief: data.message },
      finished: true,
      statusText: data.outcome || "模拟结束"
    });
    addRecord("learningRecords", {
      type: "骗局模拟",
      title: data.outcome || (data.result && data.result.outcome) || "模拟结束",
      content: (data.simulation && data.simulation.fraud_type) || "实时骗局模拟",
      result: (data.result && data.result.debrief) || data.message || ""
    });
  } catch (err) {
    statusText.value = err.message;
    error.value = true;
  } finally {
    loading.value = false;
  }
}

function resetSimulation() {
  sessionId.value = "";
  simulation.value = null;
  messages.value = [];
  riskText.value = "";
  inputText.value = "";
  result.value = null;
  finished.value = false;
  statusText.value = "";
  error.value = false;
}

onLoad(() => {
  setupNavigation();
});
</script>

<style scoped>
.page {
  min-height: 100vh;
  background: #fff;
  padding: 0 28rpx calc(28rpx + env(safe-area-inset-bottom));
  box-sizing: border-box;
}

.nav {
  height: 86rpx;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
}

.back {
  position: absolute;
  left: 0;
  width: 64rpx;
  height: 64rpx;
  border-radius: 50%;
  background: #fff;
  color: #111;
  font-size: 48rpx;
  line-height: 58rpx;
  padding: 0;
}

.nav-title {
  color: #111;
  font-size: 30rpx;
  font-weight: 650;
}

.section {
  margin-bottom: 24rpx;
}

.title {
  font-size: 42rpx;
  line-height: 1.2;
  font-weight: 700;
  color: #151515;
}

.subtitle,
.label,
.scenario-subtitle,
.risk-list,
.status {
  margin-top: 10rpx;
  font-size: 26rpx;
  line-height: 1.5;
  color: #777;
}

.surface {
  border: 1rpx solid #e8e8e8;
  border-radius: 20rpx;
  background: #fafafa;
  padding: 24rpx;
  box-sizing: border-box;
}

.picker,
.textarea {
  width: 100%;
  border: 1rpx solid #e2e2e2;
  border-radius: 18rpx;
  background: #fff;
  color: #151515;
  padding: 20rpx;
  box-sizing: border-box;
  font-size: 29rpx;
}

.picker {
  min-height: 86rpx;
  line-height: 46rpx;
  margin-top: 12rpx;
}

.textarea {
  min-height: 180rpx;
  line-height: 1.55;
}

.scenario {
  margin-bottom: 20rpx;
}

.scenario-head {
  display: flex;
  justify-content: space-between;
  gap: 18rpx;
  align-items: flex-start;
}

.scenario-title {
  font-size: 33rpx;
  font-weight: 700;
  color: #111;
}

.pill {
  flex-shrink: 0;
  max-width: 260rpx;
  border-radius: 999rpx;
  background: #eee;
  color: #333;
  padding: 10rpx 16rpx;
  font-size: 22rpx;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.messages {
  height: 520rpx;
  margin-bottom: 20rpx;
}

.msg {
  margin-bottom: 20rpx;
}

.msg.user {
  text-align: right;
}

.msg-role {
  color: #8a8a8a;
  font-size: 23rpx;
  margin-bottom: 6rpx;
}

.msg-bubble {
  display: inline-block;
  max-width: 86%;
  border-radius: 18rpx;
  background: #fff;
  color: #222;
  padding: 18rpx 20rpx;
  text-align: left;
  font-size: 28rpx;
  line-height: 1.58;
}

.msg.user .msg-bubble {
  background: #f1f1f1;
}

.final-card {
  border-radius: 16rpx;
  background: #e9f7ee;
  color: #1f693d;
  padding: 22rpx;
  font-size: 27rpx;
  line-height: 1.6;
}

.final-title {
  font-size: 32rpx;
  font-weight: 700;
}

.button-row {
  display: flex;
  gap: 18rpx;
  margin-top: 18rpx;
}

.button-row button {
  flex: 1;
}

.primary-btn,
.ghost-btn {
  min-height: 78rpx;
  border-radius: 999rpx;
  font-size: 28rpx;
  line-height: 78rpx;
}

.primary-btn {
  background: #111;
  color: #fff;
}

.ghost-btn {
  background: #f3f3f3;
  color: #222;
}

.status.error {
  color: #a23a3a;
}
</style>
