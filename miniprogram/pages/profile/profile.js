const api = require("../../utils/api");
const records = require("../../utils/records");

Page({
  data: {
    baseUrl: "",
    userId: "",
    statusText: "",
    error: false,
    summary: null,
    training: {},
    accuracyText: "0%",
    badges: [],
    learningRecords: [],
    reportRecords: []
  },

  onShow() {
    const app = getApp();
    this.setData({
      baseUrl: app.globalData.baseUrl,
      userId: app.globalData.userId
    });
    this.loadSummary();
    this.loadLocalRecords();
  },

  onBaseUrlInput(event) {
    this.setData({ baseUrl: event.detail.value });
  },

  onUserInput(event) {
    this.setData({ userId: event.detail.value });
  },

  saveSettings() {
    const app = getApp();
    app.setBaseUrl(this.data.baseUrl);
    app.setUserId(this.data.userId);
    this.setData({
      baseUrl: app.globalData.baseUrl,
      userId: app.globalData.userId,
      statusText: "已保存",
      error: false
    });
    this.loadSummary();
  },

  async checkHealth() {
    this.saveSettings();
    try {
      await api.get("/health");
      this.setData({ statusText: "后端连接正常", error: false });
    } catch (error) {
      this.setData({ statusText: error.message, error: true });
    }
  },

  async loadSummary() {
    try {
      const data = await api.get("/profile/summary", { user_id: getApp().globalData.userId });
      const training = data.training || data || {};
      this.setData({
        summary: data,
        training,
        accuracyText: `${Math.round(Number(training.accuracy || 0) * 100)}%`,
        badges: Array.isArray(training.badges) ? training.badges : [],
        error: false
      });
    } catch (error) {
      this.setData({ summary: null, training: {}, accuracyText: "0%", badges: [] });
    }
  },

  formatRecords(items) {
    return items.map((item) => ({
      ...item,
      timeText: item.time ? item.time.replace("T", " ").slice(0, 16) : ""
    }));
  },

  loadLocalRecords() {
    this.setData({
      learningRecords: this.formatRecords(records.readRecords("learningRecords")).slice(0, 20),
      reportRecords: this.formatRecords(records.readRecords("reportRecords")).slice(0, 20)
    });
  },

  clearLearningRecords() {
    records.clearRecords("learningRecords");
    this.loadLocalRecords();
  },

  clearReportRecords() {
    records.clearRecords("reportRecords");
    this.loadLocalRecords();
  }
});
