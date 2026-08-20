const api = require("../../utils/api");
const audio = require("../../utils/audio");
const records = require("../../utils/records");

const DIFFICULTIES = [
  { value: "easy", label: "简单模式" },
  { value: "medium", label: "中等模式" },
  { value: "hard", label: "困难模式" }
];

const SPEAKERS = [
  { sid: 3, label: "Kokoro 女声 1" },
  { sid: 8, label: "Kokoro 女声 2" },
  { sid: 58, label: "Kokoro 男声 1" },
  { sid: 70, label: "Kokoro 男声 2" }
];

const BAD_SCAMMER_LABELS = [
  "冒充客服",
  "可疑联系人",
  "骗子",
  "诈骗分子",
  "诈骗人员",
  "冒充公检法人员"
];

const recorder = wx.getRecorderManager();

function inferScammerIdentity(simulation) {
  const explicit = String((simulation && simulation.scammer_identity) || "").trim();
  if (explicit && !BAD_SCAMMER_LABELS.includes(explicit)) return explicit;

  const text = [
    simulation && simulation.fraud_type,
    simulation && simulation.scammer_role,
    simulation && simulation.scenario
  ].join(" ");
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
  BAD_SCAMMER_LABELS.forEach((label) => {
    value = value
      .replace(new RegExp(`我是${label}`, "g"), `我是${identity}`)
      .replace(new RegExp(`我是一名${label}`, "g"), `我是一名${identity}`)
      .replace(new RegExp(`我是一个${label}`, "g"), `我是一个${identity}`);
  });
  return value;
}

Page({
  recordingActive: false,
  recordingStartedBySimulation: false,
  recordAutoSend: false,
  recordCancelled: false,
  recordStopTimer: null,

  data: {
    difficultyLabels: DIFFICULTIES.map((item) => item.label),
    difficultyIndex: 1,
    speakerLabels: SPEAKERS.map((item) => item.label),
    speakerIndex: 0,
    sessionId: "",
    simulation: null,
    messages: [],
    riskText: "",
    inputText: "",
    loading: false,
    recording: false,
    statusText: "",
    error: false,
    result: null,
    finished: false,
    callActive: false,
    callStatus: "未通话",
    lastMessageId: ""
  },

  onLoad() {
    const savedSpeaker = Number(wx.getStorageSync("antiFraudMiniSimulationSpeakerSid") || SPEAKERS[0].sid);
    const speakerIndex = Math.max(0, SPEAKERS.findIndex((item) => item.sid === savedSpeaker));
    this.setData({ speakerIndex });
    audio.warmupTts(this.speakerSid(speakerIndex));
    recorder.onStop(async (res) => {
      if (!this.recordingStartedBySimulation) return;
      this.recordingStartedBySimulation = false;
      const shouldAutoSend = this.recordAutoSend;
      const cancelled = this.recordCancelled;
      this.recordingActive = false;
      this.recordAutoSend = false;
      this.recordCancelled = false;
      clearTimeout(this.recordStopTimer);
      if (cancelled) {
        this.setData({ recording: false, statusText: "", error: false });
        return;
      }
      this.setData({ recording: false, statusText: "正在识别语音", error: false });
      try {
        const asr = await audio.transcribeAudioFile(res.tempFilePath, { audioFormat: "wav", sampleRate: 16000 });
        const text = String(asr.text || "").trim();
        if (shouldAutoSend) {
          if (!text) {
            const bytes = asr.meta && asr.meta.audio_bytes ? `录音 ${Math.round(asr.meta.audio_bytes / 1024)}KB` : "未拿到有效录音";
            this.setData({ statusText: `没有听清（${bytes}），请说一句完整回应`, callStatus: "正在听你说话", error: false });
            if (this.data.callActive) this.startRecord({ autoSend: true });
            return;
          }
          await this.sendTurn(text, { inputMode: "voice", fromCall: true });
          return;
        }
        const bytes = asr.meta && asr.meta.audio_bytes ? `，录音 ${Math.round(asr.meta.audio_bytes / 1024)}KB` : "";
        this.setData({ inputText: text, statusText: text ? "语音识别完成" : `没有听清${bytes}。请说一句完整回应。`, error: false });
      } catch (error) {
        this.setData({ statusText: error.message, error: true, callStatus: this.data.callActive ? "识别失败" : this.data.callStatus });
      }
    });
    recorder.onError((error) => {
      if (!this.recordingStartedBySimulation) return;
      this.recordingStartedBySimulation = false;
      this.recordingActive = false;
      this.recordAutoSend = false;
      this.recordCancelled = false;
      clearTimeout(this.recordStopTimer);
      this.setData({ recording: false, statusText: error.errMsg || "录音失败", error: true });
    });
  },

  onUnload() {
    clearTimeout(this.recordStopTimer);
    if (this.recordingActive || this.data.recording) {
      this.recordCancelled = true;
      try {
        recorder.stop();
      } catch (error) {
        this.recordingStartedBySimulation = false;
        // Page is leaving; the recorder may already be stopped.
      }
    }
  },

  userId() {
    return getApp().globalData.userId || "demo_user";
  },

  onDifficultyChange(event) {
    this.setData({ difficultyIndex: Number(event.detail.value || 0) });
  },

  onSpeakerChange(event) {
    const speakerIndex = Number(event.detail.value || 0);
    this.setData({ speakerIndex, statusText: "音色已切换", error: false });
    wx.setStorageSync("antiFraudMiniSimulationSpeakerSid", this.speakerSid(speakerIndex));
    audio.warmupTts(this.speakerSid(speakerIndex));
  },

  speakerSid(index = this.data.speakerIndex) {
    return (SPEAKERS[index] || SPEAKERS[0]).sid;
  },

  onInput(event) {
    this.setData({ inputText: event.detail.value });
  },

  messageItems(simulation) {
    const identity = inferScammerIdentity(simulation);
    return (simulation && simulation.messages ? simulation.messages : []).map((item, index) => ({
      id: `msg-${index}`,
      role: item.role,
      roleLabel: item.role === "scammer" ? "对方" : "我",
      content: item.role === "scammer" ? sanitizeScammerText(item.content || item.text || "", identity) : (item.content || item.text || "")
    }));
  },

  applySimulation(simulation, extra = {}) {
    const identity = inferScammerIdentity(simulation);
    const normalizedSimulation = {
      ...simulation,
      scammer_identity: identity
    };
    const messages = this.messageItems(normalizedSimulation);
    this.setData({
      simulation: normalizedSimulation,
      sessionId: normalizedSimulation.session_id || this.data.sessionId,
      messages,
      riskText: (normalizedSimulation.risk_signals || []).join("、"),
      lastMessageId: messages.length ? messages[messages.length - 1].id : "",
      ...extra
    });
  },

  async startSimulation(options = {}) {
    const opts = options && options.currentTarget ? {} : options;
    this.setData({ loading: true, statusText: "正在启动模拟", error: false, result: null, finished: false });
    try {
      const difficulty = DIFFICULTIES[this.data.difficultyIndex].value;
      const data = await api.post("/game/simulation/start", {
        user_id: this.userId(),
        difficulty,
        use_llm: true
      });
      this.applySimulation(data.simulation, { statusText: "模拟已开始" });
      await this.speakText(sanitizeScammerText(data.scammer_message, inferScammerIdentity(data.simulation)), {
        continueCall: Boolean(opts.fromCall || this.data.callActive)
      });
    } catch (error) {
      this.setData({ statusText: error.message, error: true });
    } finally {
      this.setData({ loading: false });
    }
  },

  async sendTurn(textOverride = "", options = {}) {
    const providedText = typeof textOverride === "string" ? textOverride : "";
    const text = String(providedText || this.data.inputText || "").trim();
    if (!text || this.data.loading) return;
    const fromCall = Boolean(options.fromCall);
    this.setData({
      loading: true,
      statusText: "正在生成回应",
      callStatus: fromCall ? "对方正在回应" : this.data.callStatus,
      error: false
    });
    try {
      const data = await api.post("/game/simulation/turn", {
        session_id: this.data.sessionId,
        user_message: options.inputMode === "voice" ? "" : text,
        voice_text: options.inputMode === "voice" ? text : "",
        use_llm: true
      });
      const finished = Boolean(data.result || data.outcome || (data.simulation && data.simulation.status === "finished"));
      if (finished) this.stopCall(false);
      this.applySimulation(data.simulation, {
        inputText: "",
        result: data.result || (finished ? { score: data.score, outcome: data.outcome, debrief: data.message } : null),
        finished,
        callActive: finished ? false : this.data.callActive,
        callStatus: finished ? "通话已结束" : this.data.callStatus,
        statusText: data.message || ""
      });
      if (finished) {
        records.addRecord("learningRecords", {
          type: "骗局模拟",
          title: data.outcome || (data.result && data.result.outcome) || "模拟结束",
          content: (data.simulation && data.simulation.fraud_type) || "实时骗局模拟",
          result: (data.result && data.result.debrief) || data.message || ""
        });
      }
      if (data.scammer_message) {
        await this.speakText(sanitizeScammerText(data.scammer_message, inferScammerIdentity(data.simulation)), {
          continueCall: fromCall || this.data.callActive
        });
      }
    } catch (error) {
      this.setData({ statusText: error.message, error: true, callStatus: fromCall ? "发送失败" : this.data.callStatus });
    } finally {
      this.setData({ loading: false });
    }
  },

  async finishSimulation() {
    if (!this.data.sessionId || this.data.loading) return;
    this.stopCall(false);
    this.setData({ loading: true, statusText: "正在评分", error: false });
    try {
      const data = await api.post("/game/simulation/finish", {
        session_id: this.data.sessionId,
        user_message: this.data.inputText || undefined
      });
      this.applySimulation(data.simulation, {
        inputText: "",
        result: data.result || { score: data.score, outcome: data.outcome, debrief: data.message },
        finished: true,
        statusText: data.outcome || "模拟结束"
      });
      records.addRecord("learningRecords", {
        type: "骗局模拟",
        title: data.outcome || (data.result && data.result.outcome) || "模拟结束",
        content: (data.simulation && data.simulation.fraud_type) || "实时骗局模拟",
        result: (data.result && data.result.debrief) || data.message || ""
      });
    } catch (error) {
      this.setData({ statusText: error.message, error: true });
    } finally {
      this.setData({ loading: false });
    }
  },

  toggleRecord() {
    if (this.recordingActive || this.data.recording) {
      this.stopRecord();
      return;
    }
    this.startRecord({ autoSend: false });
  },

  async startRecord(options = {}) {
    if (this.recordingActive || this.data.recording) return;
    clearTimeout(this.recordStopTimer);
    try {
      this.setData({ statusText: "正在请求麦克风权限", error: false });
      await audio.ensureRecordPermission();
      this.recordingActive = true;
      this.recordingStartedBySimulation = true;
      this.recordAutoSend = Boolean(options.autoSend);
      this.recordCancelled = false;
      this.setData({ recording: true, statusText: "正在录音，说完后点停止", error: false });
      recorder.start({
        duration: 15000,
        sampleRate: 16000,
        numberOfChannels: 1,
        encodeBitRate: 64000,
        format: "wav"
      });
    } catch (error) {
      this.recordingActive = false;
      this.recordingStartedBySimulation = false;
      this.recordAutoSend = false;
      this.setData({ recording: false, statusText: error.errMsg || error.message || "录音启动失败", error: true });
    }
  },

  stopRecord() {
    this.recordingActive = false;
    this.setData({ recording: false, statusText: "正在停止录音", error: false });
    try {
      recorder.stop();
    } catch (error) {
      this.recordingStartedBySimulation = false;
      clearTimeout(this.recordStopTimer);
      this.setData({ statusText: error.errMsg || error.message || "录音已停止", error: Boolean(error.errMsg || error.message) });
      return;
    }
    clearTimeout(this.recordStopTimer);
    this.recordStopTimer = setTimeout(() => {
      if (!this.recordingActive && !this.data.recording && this.data.statusText === "正在停止录音") {
        this.setData({ statusText: "录音已停止，等待识别结果" });
      }
    }, 1200);
  },

  replayLastScammer() {
    const last = [...this.data.messages].reverse().find((item) => item.role === "scammer");
    if (last) this.speakText(last.content, { continueCall: false });
  },

  async speakText(text, options = {}) {
    if (!text) return;
    const continueCall = options.continueCall !== false;
    try {
      this.setData({ callStatus: this.data.callActive ? "对方说话中" : this.data.callStatus });
      await audio.speakWithKokoro(text, this.speakerSid());
      if (continueCall && this.data.callActive && !this.data.finished) {
        this.setData({ callStatus: "正在听你说话", statusText: "电话模式：请直接说出回应", error: false });
        this.startRecord({ autoSend: true });
      }
    } catch (error) {
      this.setData({ statusText: `TTS 播放失败：${error.message}`, error: true });
      if (continueCall && this.data.callActive && !this.data.finished) {
        this.setData({ callStatus: "正在听你说话" });
        this.startRecord({ autoSend: true });
      }
    }
  },

  async toggleCall() {
    if (this.data.callActive) {
      this.stopCall();
      return;
    }
    this.setData({ callActive: true, callStatus: "正在接通", statusText: "电话模式已开启", error: false });
    audio.warmupTts(this.speakerSid());
    if (!this.data.sessionId) {
      await this.startSimulation({ fromCall: true });
      return;
    }
    this.setData({ callStatus: "正在听你说话" });
    this.startRecord({ autoSend: true });
  },

  stopCall(updateStatus = true) {
    audio.stopPlayback();
    if (this.recordingActive || this.data.recording) {
      this.recordCancelled = true;
      this.recordAutoSend = false;
      try {
        recorder.stop();
      } catch (error) {
        this.recordingActive = false;
        this.recordingStartedBySimulation = false;
      }
    }
    this.setData({
      callActive: false,
      callStatus: updateStatus ? "通话已挂断" : "未通话",
      recording: false
    });
  },

  resetSimulation() {
    this.stopCall(false);
    this.setData({
      sessionId: "",
      simulation: null,
      messages: [],
      riskText: "",
      inputText: "",
      result: null,
      finished: false,
      callActive: false,
      callStatus: "未通话",
      statusText: "",
      error: false
    });
  }
});
