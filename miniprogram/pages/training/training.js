const api = require("../../utils/api");
const records = require("../../utils/records");

function toOptions(level, selectedAnswer = "") {
  return (level && level.options ? level.options : []).map((text) => ({
    text,
    selected: text === selectedAnswer
  }));
}

function buildBattle(level, progress, result) {
  const levelId = Number((level && (level.level_id || level.level_no)) || 1);
  const total = Number((level && level.total_levels) || (progress && progress.total_levels) || 200);
  const stageSize = 10;
  const stageIndex = Math.max(0, Math.floor((levelId - 1) / stageSize));
  const stageNo = stageIndex + 1;
  const totalStages = Math.max(1, Math.ceil(total / stageSize));
  const startLevel = stageIndex * stageSize + 1;
  const currentQuestion = ((levelId - 1) % stageSize) + 1;
  const completed = new Set((progress && progress.completed_levels ? progress.completed_levels : []).map(Number));
  if (result && result.correct) completed.add(levelId);
  const correctCount = Array.from({ length: stageSize }, (_, index) => startLevel + index)
    .filter((id) => completed.has(id)).length;
  const bossHp = Math.max(0, stageSize - correctCount);
  const nodes = Array.from({ length: totalStages }, (_, index) => {
    const nodeStart = index * stageSize + 1;
    const nodeIds = Array.from({ length: stageSize }, (_, offset) => nodeStart + offset).filter((id) => id <= total);
    const cleared = nodeIds.length > 0 && nodeIds.every((id) => completed.has(id));
    const locked = index > stageIndex && !cleared;
    return {
      stageNo: index + 1,
      levelId: nodeStart,
      className: index === stageIndex ? "current" : cleared ? "cleared" : locked ? "locked" : ""
    };
  });
  const dots = Array.from({ length: stageSize }, (_, index) => {
    const no = index + 1;
    const id = startLevel + index;
    const failed = result && !result.correct && id === levelId;
    return {
      no,
      className: completed.has(id) ? "done" : failed ? "failed" : no === currentQuestion ? "current" : ""
    };
  });
  return {
    stageNo,
    stageName: (level && (level.fraud_type || level.chapter || level.title)) || "反诈闯关",
    bossName: (level && level.scenario_simulation && level.scenario_simulation.opponent_role) || "诱导骗子",
    currentQuestion,
    stageSize,
    bossHp,
    bossHpPercent: Math.round((bossHp / stageSize) * 100),
    nodes,
    dots
  };
}

Page({
  data: {
    level: null,
    report: {},
    battle: buildBattle(null, {}, null),
    options: [],
    selectedAnswer: "",
    result: null,
    scenarioText: "",
    questionText: "",
    loading: false,
    submitting: false,
    statusText: "",
    error: false,
    accuracyText: "0%"
  },

  onShow() {
    this.loadReport();
    if (!this.data.level) this.loadLevel();
  },

  userId() {
    return getApp().globalData.userId || "demo_user";
  },

  async loadReport() {
    try {
      const report = await api.get("/game/report", { user_id: this.userId() });
      const accuracy = Math.round(Number(report.accuracy || 0) * 100);
      this.setData({
        report,
        accuracyText: `${accuracy}%`,
        battle: buildBattle(this.data.level, report, this.data.result)
      });
    } catch (error) {
      this.setData({ report: {}, accuracyText: "0%" });
    }
  },

  async loadLevel(levelId) {
    this.setData({ loading: true, statusText: "正在加载关卡", error: false });
    try {
      const data = await api.get("/game/next", {
        user_id: this.userId(),
        level_id: levelId
      });
      const level = data.level || null;
      const progress = data.progress || this.data.report || {};
      this.setData({
        level,
        scenarioText: (level && (level.scenario || (level.scenario_simulation && level.scenario_simulation.opening_line))) || "",
        questionText: (level && (level.question || (level.scenario_simulation && level.scenario_simulation.mission))) || "",
        options: toOptions(level),
        battle: buildBattle(level, progress, null),
        selectedAnswer: "",
        result: null,
        statusText: "",
        error: false
      });
    } catch (error) {
      this.setData({ statusText: error.message, error: true });
    } finally {
      this.setData({ loading: false });
    }
  },

  reloadLevel() {
    const levelId = this.data.level && (this.data.level.level_id || this.data.level.level_no);
    this.loadLevel(levelId);
    this.loadReport();
  },

  selectOption(event) {
    if (this.data.result) return;
    const selectedAnswer = event.currentTarget.dataset.value;
    this.setData({
      selectedAnswer,
      options: toOptions(this.data.level, selectedAnswer)
    });
  },

  async submitAnswer() {
    if (!this.data.level || !this.data.selectedAnswer || this.data.submitting) return;
    this.setData({ submitting: true, statusText: "正在提交", error: false });
    try {
      const result = await api.post("/game/submit", {
        user_id: this.userId(),
        level_id: this.data.level.level_id || this.data.level.level_no,
        answer: this.data.selectedAnswer,
        interaction_mode: "choice"
      });
      this.setData({
        result,
        battle: buildBattle(this.data.level, result.progress || this.data.report, result),
        statusText: result.message || "答题完成",
        error: false
      });
      records.addRecord("learningRecords", {
        type: "训练答题",
        title: this.data.level.title || this.data.level.fraud_type || "防骗训练营",
        content: this.data.selectedAnswer,
        result: result.correct ? "回答正确" : "回答错误"
      });
      this.loadReport();
    } catch (error) {
      this.setData({ statusText: error.message, error: true });
    } finally {
      this.setData({ submitting: false });
    }
  },

  nextLevel() {
    const nextId = this.data.result && this.data.result.next_level_id;
    this.loadLevel(nextId);
  },

  jumpStage(event) {
    const levelId = Number(event.currentTarget.dataset.levelId || 0);
    if (levelId) this.loadLevel(levelId);
  }
});
