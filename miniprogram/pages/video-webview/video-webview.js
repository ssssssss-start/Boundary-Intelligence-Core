Page({
  data: {
    sourceUrl: ""
  },

  onLoad(options = {}) {
    let sourceUrl = String(options.url || "").trim();
    try {
      sourceUrl = decodeURIComponent(sourceUrl);
    } catch (error) {
      sourceUrl = "";
    }
    if (!/^https?:\/\//i.test(sourceUrl)) {
      wx.showToast({ title: "官方链接暂不可用", icon: "none" });
      return;
    }
    this.setData({ sourceUrl });
  }
});
