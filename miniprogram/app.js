const { DEFAULT_BASE_URL, normalizeBaseUrl } = require("./utils/api");

App({
  globalData: {
    baseUrl: DEFAULT_BASE_URL,
    userId: "demo_user"
  },

  onLaunch() {
    const savedBaseUrl = wx.getStorageSync("antiFraudBaseUrl");
    const savedUserId = wx.getStorageSync("antiFraudUserId");
    if (savedBaseUrl) this.globalData.baseUrl = normalizeBaseUrl(savedBaseUrl);
    if (savedUserId) this.globalData.userId = String(savedUserId);
  },

  setBaseUrl(value) {
    this.globalData.baseUrl = normalizeBaseUrl(value || DEFAULT_BASE_URL);
    wx.setStorageSync("antiFraudBaseUrl", this.globalData.baseUrl);
  },

  setUserId(value) {
    this.globalData.userId = String(value || "demo_user").trim() || "demo_user";
    wx.setStorageSync("antiFraudUserId", this.globalData.userId);
  }
});
