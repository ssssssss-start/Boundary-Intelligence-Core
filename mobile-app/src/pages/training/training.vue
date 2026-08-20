<template>
  <view class="page" :style="{ paddingTop: navTop + 'px' }">
    <view class="nav">
      <button class="back" @tap="goBack">‹</button>
      <view class="nav-title">防骗训练营</view>
    </view>

    <view class="section">
      <view class="title">防骗训练营</view>
      <view class="subtitle">识别骗局信号，选择最安全的处置方式。</view>
    </view>

    <view class="stats section">
      <view class="stat-card">
        <text>积分</text>
        <strong>{{ report.score || 0 }}</strong>
      </view>
      <view class="stat-card">
        <text>段位</text>
        <strong>{{ report.rank_badge || report.assessment_level || '未测评' }}</strong>
      </view>
      <view class="stat-card">
        <text>正确率</text>
        <strong>{{ accuracyText }}</strong>
      </view>
    </view>

    <view v-if="level" class="surface level-card">
      <view class="battle-head">
        <view>
          <view class="battle-title">第 {{ battle.stageNo }} 关 · {{ battle.stageName }}</view>
          <view class="battle-subtitle">第 {{ battle.currentQuestion }}/{{ battle.stageSize }} 题 · 守关骗子：{{ battle.bossName }}</view>
        </view>
        <view class="hp-pill">血量 {{ battle.bossHp }}/{{ battle.stageSize }}</view>
      </view>

      <scroll-view class="stage-map" scroll-x>
        <view
          v-for="item in battle.nodes"
          :key="item.stageNo"
          class="stage-node"
          :class="item.className"
          @tap="jumpStage(item.levelId)"
        >
          {{ item.stageNo }}
        </view>
      </scroll-view>

      <view class="hp-wrap">
        <view class="hp-label">
          <text>骗子血量</text>
          <text>{{ battle.bossHp }}/{{ battle.stageSize }}</text>
        </view>
        <view class="hp-track">
          <view class="hp-fill" :style="{ width: battle.bossHpPercent + '%' }"></view>
        </view>
      </view>

      <view class="progress-dots">
        <view v-for="item in battle.dots" :key="item.no" class="dot" :class="item.className">{{ item.no }}</view>
      </view>

      <view class="level-meta">
        <text>第 {{ level.level_no || level.level_id }} 题</text>
        <text>{{ level.difficulty || '基础' }}</text>
      </view>
      <view class="level-title">{{ level.title || level.chapter || '反诈闯关' }}</view>
      <view class="scenario">{{ scenarioText }}</view>
      <view class="question">{{ questionText }}</view>

      <view class="options">
        <view
          v-for="(item, index) in options"
          :key="item.text"
          class="option"
          :class="{ selected: item.selected }"
          @tap="selectOption(item.text)"
        >
          {{ index + 1 }}. {{ item.text }}
        </view>
      </view>

      <view v-if="result" class="result" :class="result.correct ? 'correct' : 'wrong'">
        <view class="result-title">{{ result.correct ? '回答正确' : '回答错误' }}</view>
        <view>你的选择：{{ result.selected_answer || selectedAnswer }}</view>
        <view>正确答案：{{ result.answer }}</view>
        <view v-if="result.explanation">解析：{{ result.explanation }}</view>
      </view>

      <view class="button-row">
        <button class="ghost-btn" :loading="loading" :disabled="loading" @tap="reloadLevel">刷新</button>
        <button v-if="!result" class="primary-btn" :loading="submitting" :disabled="submitting || !selectedAnswer" @tap="submitAnswer">提交答案</button>
        <button v-else class="primary-btn" :loading="loading" :disabled="loading" @tap="nextLevel">下一题</button>
      </view>
    </view>

    <view v-else class="surface empty-card">
      <view class="subtitle">{{ statusText || '正在加载关卡' }}</view>
      <button class="primary-btn" :loading="loading" @tap="reloadLevel">重新加载</button>
    </view>

    <view v-if="statusText" class="status" :class="{ error }">{{ statusText }}</view>
  </view>
</template>

<script setup>
import { ref } from "vue";
import { onShow } from "@dcloudio/uni-app";
import { get, post } from "../../utils/api";
import { addRecord, currentUserId } from "../../utils/storage";

const navTop = ref(36);
const level = ref(null);
const report = ref({});
const battle = ref(buildBattle(null, {}, null));
const options = ref([]);
const selectedAnswer = ref("");
const result = ref(null);
const scenarioText = ref("");
const questionText = ref("");
const loading = ref(false);
const submitting = ref(false);
const statusText = ref("");
const error = ref(false);
const accuracyText = ref("0%");

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

function toOptions(nextLevel, selected = "") {
  return (nextLevel && nextLevel.options ? nextLevel.options : []).map((text) => ({
    text,
    selected: text === selected
  }));
}

function buildBattle(nextLevel, progress, nextResult) {
  const levelId = Number((nextLevel && (nextLevel.level_id || nextLevel.level_no)) || 1);
  const total = Number((nextLevel && nextLevel.total_levels) || (progress && progress.total_levels) || 200);
  const stageSize = 10;
  const stageIndex = Math.max(0, Math.floor((levelId - 1) / stageSize));
  const stageNo = stageIndex + 1;
  const totalStages = Math.max(1, Math.ceil(total / stageSize));
  const startLevel = stageIndex * stageSize + 1;
  const currentQuestion = ((levelId - 1) % stageSize) + 1;
  const completed = new Set((progress && progress.completed_levels ? progress.completed_levels : []).map(Number));
  if (nextResult && nextResult.correct) completed.add(levelId);
  const correctCount = Array.from({ length: stageSize }, (_, index) => startLevel + index).filter((id) => completed.has(id)).length;
  const bossHp = Math.max(0, stageSize - correctCount);
  return {
    stageNo,
    stageName: (nextLevel && (nextLevel.fraud_type || nextLevel.chapter || nextLevel.title)) || "反诈闯关",
    bossName: (nextLevel && nextLevel.scenario_simulation && nextLevel.scenario_simulation.opponent_role) || "诱导骗子",
    currentQuestion,
    stageSize,
    bossHp,
    bossHpPercent: Math.round((bossHp / stageSize) * 100),
    nodes: Array.from({ length: totalStages }, (_, index) => {
      const nodeStart = index * stageSize + 1;
      const nodeIds = Array.from({ length: stageSize }, (_, offset) => nodeStart + offset).filter((id) => id <= total);
      const cleared = nodeIds.length > 0 && nodeIds.every((id) => completed.has(id));
      const locked = index > stageIndex && !cleared;
      return {
        stageNo: index + 1,
        levelId: nodeStart,
        className: index === stageIndex ? "current" : cleared ? "cleared" : locked ? "locked" : ""
      };
    }),
    dots: Array.from({ length: stageSize }, (_, index) => {
      const no = index + 1;
      const id = startLevel + index;
      const failed = nextResult && !nextResult.correct && id === levelId;
      return {
        no,
        className: completed.has(id) ? "done" : failed ? "failed" : no === currentQuestion ? "current" : ""
      };
    })
  };
}

async function loadReport() {
  try {
    const data = await get("/game/report", { user_id: currentUserId() });
    const accuracy = Math.round(Number(data.accuracy || 0) * 100);
    report.value = data;
    accuracyText.value = `${accuracy}%`;
    battle.value = buildBattle(level.value, data, result.value);
  } catch (err) {
    report.value = {};
    accuracyText.value = "0%";
  }
}

async function loadLevel(levelId) {
  loading.value = true;
  statusText.value = "正在加载关卡";
  error.value = false;
  try {
    const data = await get("/game/next", { user_id: currentUserId(), level_id: levelId });
    const nextLevel = data.level || null;
    const progress = data.progress || report.value || {};
    level.value = nextLevel;
    scenarioText.value = (nextLevel && (nextLevel.scenario || (nextLevel.scenario_simulation && nextLevel.scenario_simulation.opening_line))) || "";
    questionText.value = (nextLevel && (nextLevel.question || (nextLevel.scenario_simulation && nextLevel.scenario_simulation.mission))) || "";
    options.value = toOptions(nextLevel);
    battle.value = buildBattle(nextLevel, progress, null);
    selectedAnswer.value = "";
    result.value = null;
    statusText.value = "";
  } catch (err) {
    statusText.value = err.message;
    error.value = true;
  } finally {
    loading.value = false;
  }
}

function reloadLevel() {
  const levelId = level.value && (level.value.level_id || level.value.level_no);
  loadLevel(levelId);
  loadReport();
}

function selectOption(value) {
  if (result.value) return;
  selectedAnswer.value = value;
  options.value = toOptions(level.value, value);
}

async function submitAnswer() {
  if (!level.value || !selectedAnswer.value || submitting.value) return;
  submitting.value = true;
  statusText.value = "正在提交";
  error.value = false;
  try {
    const data = await post("/game/submit", {
      user_id: currentUserId(),
      level_id: level.value.level_id || level.value.level_no,
      answer: selectedAnswer.value,
      interaction_mode: "choice"
    });
    result.value = data;
    battle.value = buildBattle(level.value, data.progress || report.value, data);
    statusText.value = data.message || "答题完成";
    addRecord("learningRecords", {
      type: "训练答题",
      title: level.value.title || level.value.fraud_type || "防骗训练营",
      content: selectedAnswer.value,
      result: data.correct ? "回答正确" : "回答错误"
    });
    loadReport();
  } catch (err) {
    statusText.value = err.message;
    error.value = true;
  } finally {
    submitting.value = false;
  }
}

function nextLevel() {
  loadLevel(result.value && result.value.next_level_id);
}

function jumpStage(levelId) {
  if (levelId) loadLevel(levelId);
}

onShow(() => {
  setupNavigation();
  loadReport();
  if (!level.value) loadLevel();
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

.subtitle {
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

.stats {
  display: flex;
  gap: 14rpx;
}

.stat-card {
  flex: 1;
  min-height: 118rpx;
  border: 1rpx solid #e8e8e8;
  border-radius: 16rpx;
  background: #fafafa;
  padding: 18rpx;
  box-sizing: border-box;
}

.stat-card text {
  display: block;
  color: #777;
  font-size: 23rpx;
}

.stat-card strong {
  display: block;
  margin-top: 10rpx;
  color: #151515;
  font-size: 29rpx;
  font-weight: 700;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.battle-head {
  display: flex;
  justify-content: space-between;
  gap: 18rpx;
  align-items: flex-start;
  border-radius: 16rpx;
  background: #111;
  padding: 24rpx;
  color: #fff;
}

.battle-title {
  font-size: 32rpx;
  line-height: 1.35;
  font-weight: 700;
}

.battle-subtitle {
  margin-top: 8rpx;
  font-size: 24rpx;
  line-height: 1.45;
  color: #eee;
}

.hp-pill {
  flex-shrink: 0;
  min-height: 48rpx;
  border-radius: 999rpx;
  background: rgba(255, 255, 255, 0.18);
  padding: 0 16rpx;
  font-size: 23rpx;
  line-height: 48rpx;
}

.stage-map {
  white-space: nowrap;
  margin-top: 18rpx;
}

.stage-node {
  width: 58rpx;
  height: 50rpx;
  margin-right: 10rpx;
  border: 1rpx solid #ddd;
  border-radius: 12rpx;
  background: #fff;
  color: #777;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 23rpx;
  font-weight: 700;
}

.stage-node.current,
.dot.current {
  background: #111;
  color: #fff;
}

.stage-node.cleared,
.dot.done {
  background: #e9f7ee;
  color: #1f693d;
}

.stage-node.locked {
  opacity: 0.55;
}

.hp-wrap,
.progress-dots,
.level-meta,
.level-title,
.scenario,
.question,
.options,
.result,
.button-row {
  margin-top: 18rpx;
}

.hp-label,
.level-meta {
  display: flex;
  justify-content: space-between;
  color: #555;
  font-size: 24rpx;
  font-weight: 700;
}

.hp-track {
  margin-top: 8rpx;
  height: 18rpx;
  border-radius: 999rpx;
  background: #e4e4e4;
  overflow: hidden;
}

.hp-fill {
  height: 100%;
  border-radius: inherit;
  background: #111;
}

.progress-dots {
  display: flex;
  gap: 8rpx;
}

.dot {
  flex: 1;
  height: 34rpx;
  border-radius: 999rpx;
  background: #eee;
  color: #777;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20rpx;
}

.dot.failed {
  background: #fff0eb;
  color: #8a3a31;
}

.level-title {
  color: #111;
  font-size: 36rpx;
  font-weight: 700;
  line-height: 1.3;
}

.scenario {
  border-radius: 14rpx;
  background: #fff;
  color: #333;
  padding: 22rpx;
  font-size: 28rpx;
  line-height: 1.7;
}

.question {
  color: #111;
  font-size: 30rpx;
  font-weight: 700;
  line-height: 1.5;
}

.options {
  display: flex;
  flex-direction: column;
  gap: 16rpx;
}

.option {
  min-height: 88rpx;
  border: 1rpx solid #e0e0e0;
  border-radius: 16rpx;
  background: #fff;
  color: #222;
  padding: 20rpx 22rpx;
  box-sizing: border-box;
  font-size: 28rpx;
  line-height: 1.5;
}

.option.selected {
  border-color: #111;
  background: #f1f1f1;
  font-weight: 700;
}

.result {
  border-radius: 16rpx;
  padding: 22rpx;
  font-size: 27rpx;
  line-height: 1.65;
}

.result.correct {
  background: #e9f7ee;
  color: #1f693d;
}

.result.wrong {
  background: #fff0eb;
  color: #8a3a31;
}

.result-title {
  font-weight: 700;
  font-size: 30rpx;
}

.button-row {
  display: flex;
  gap: 18rpx;
}

.button-row button,
.empty-card .primary-btn {
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

.status {
  margin-top: 14rpx;
  color: #777;
  font-size: 25rpx;
}

.status.error {
  color: #a23a3a;
}
</style>
