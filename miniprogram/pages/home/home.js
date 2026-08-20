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
    wx.redirectTo({
      url: "/pages/chat/chat",
      complete: () => {
        this.redirecting = false;
      }
    });
  }
});
