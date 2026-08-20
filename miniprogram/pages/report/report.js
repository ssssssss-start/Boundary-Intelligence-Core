const api = require("../../utils/api");
const records = require("../../utils/records");

function asList(value) {
  if (Array.isArray(value)) return value.filter(Boolean).map(String);
  if (!value) return [];
  return [String(value)];
}

Page({
  data: {
    content: "",
    loading: false,
    confirming: false,
    confirmed: false,
    statusText: "",
    error: false,
    analysis: null,
    matchedRules: [],
    advice: []
  },

  onInput(event) {
    this.setData({ content: event.detail.value });
  },

  clear() {
    this.setData({
      content: "",
      statusText: "",
      error: false,
      analysis: null,
      matchedRules: [],
      advice: [],
      confirmed: false
    });
  },

  async analyze() {
    const content = String(this.data.content || "").trim();
    if (!content || this.data.loading) return;
    this.setData({ loading: true, statusText: "正在研判", error: false, confirmed: false });
    try {
      const analysis = await api.post("/report-intel/analyze", { content });
      this.setData({
        analysis,
        matchedRules: asList(analysis.matched_rules),
        advice: asList(analysis.advice),
        statusText: analysis.message || "研判完成",
        error: false
      });
      records.addRecord("reportRecords", {
        type: "举报研判",
        title: analysis.suspected_type || analysis.fraud_type || analysis.risk_level || "研判结果",
        content,
        result: analysis.display_summary || analysis.answer || analysis.message || ""
      });
    } catch (error) {
      this.setData({ statusText: error.message, error: true });
    } finally {
      this.setData({ loading: false });
    }
  },

  async confirmReport() {
    if (!this.data.analysis || this.data.confirming) return;
    this.setData({ confirming: true, statusText: "正在确认举报", error: false });
    try {
      const data = await api.post("/report-intel/confirm", {
        analysis_id: this.data.analysis.analysis_id,
        reporter_note: "来自微信小程序确认"
      });
      this.setData({
        confirmed: true,
        statusText: data.report_id ? `举报已确认：${data.report_id}` : data.message || "举报已确认",
        error: false
      });
      records.addRecord("reportRecords", {
        type: "确认举报",
        title: data.report_id || "举报已确认",
        content: this.data.content,
        result: data.message || "举报已确认"
      });
    } catch (error) {
      this.setData({ statusText: error.message, error: true });
    } finally {
      this.setData({ confirming: false });
    }
  }
});
