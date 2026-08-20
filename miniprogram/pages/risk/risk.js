const api = require("../../utils/api");
const records = require("../../utils/records");

function compact(value) {
  if (Array.isArray(value)) return value.filter(Boolean).join("、");
  if (value && typeof value === "object") return Object.keys(value).join("、");
  return value ? String(value) : "";
}

Page({
  data: {
    mode: "text",
    content: "",
    loading: false,
    statusText: "",
    error: false,
    result: null,
    rulesText: "",
    adviceText: "",
    rawResult: ""
  },

  switchMode(event) {
    this.setData({ mode: event.currentTarget.dataset.mode, result: null, statusText: "", error: false });
  },

  onInput(event) {
    this.setData({ content: event.detail.value });
  },

  async submitCheck() {
    const content = String(this.data.content || "").trim();
    if (!content || this.data.loading) return;
    this.setData({ loading: true, statusText: "正在检测", error: false, result: null });
    try {
      const result = this.data.mode === "url"
        ? await api.post("/url/check", { content })
        : await api.post("/risk/check", { user_text: content });
      const advice = result.advice || result.suggestions || result.actions || "";
      this.setData({
        result,
        rulesText: compact(result.risk_rules || result.rules || result.matched_rules),
        adviceText: compact(advice),
        rawResult: JSON.stringify(result, null, 2),
        statusText: "检测完成",
        error: false
      });
      records.addRecord("learningRecords", {
        type: this.data.mode === "url" ? "链接检测" : "风险检测",
        title: result.risk_level || result.scam_type || result.fraud_type || "检测结果",
        content,
        result: compact(advice) || result.message || ""
      });
    } catch (error) {
      this.setData({ statusText: error.message, error: true });
    } finally {
      this.setData({ loading: false });
    }
  }
});
