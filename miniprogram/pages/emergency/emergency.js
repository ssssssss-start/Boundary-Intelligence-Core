const PENDING_CHAT_KEY = "antiFraudMini:pendingChatIntent";

Page({
  redirecting: false,

  onLoad() {
    this.redirectToAssistant();
  },

  onShow() {
    this.redirectToAssistant();
  },

  redirectToAssistant() {
    if (this.redirecting) return;
    this.redirecting = true;
    wx.setStorageSync(PENDING_CHAT_KEY, {
      mode: "risk",
      prompt: "我正在遇到紧急风险，请先帮我判断现在应该怎么做："
    });
    wx.redirectTo({
      url: "/pages/chat/chat",
      complete: () => {
        this.redirecting = false;
      }
    });
  }
});
