const api = require("./api");

let audioContext = null;

function ensureRecordPermission() {
  return new Promise((resolve, reject) => {
    wx.getSetting({
      success(setting) {
        const auth = setting.authSetting || {};
        if (auth["scope.record"]) {
          resolve();
          return;
        }
        if (auth["scope.record"] === false) {
          reject(new Error("麦克风权限未开启，请在小程序设置里允许录音权限。"));
          return;
        }
        wx.authorize({
          scope: "scope.record",
          success: resolve,
          fail() {
            reject(new Error("未获得麦克风权限，无法语音识别。"));
          }
        });
      },
      fail(error) {
        reject(new Error(error.errMsg || "无法检查麦克风权限"));
      }
    });
  });
}

function requestTtsAudio(text, sid = 3) {
  return new Promise((resolve, reject) => {
    wx.request({
      url: `${api.appBaseUrl()}/game/simulation/tts`,
      method: "POST",
      data: { text, sid, speed: 1.0 },
      responseType: "arraybuffer",
      timeout: 45000,
      header: { "Content-Type": "application/json" },
      success(resp) {
        if (resp.statusCode >= 200 && resp.statusCode < 300 && resp.data) {
          resolve(resp.data);
          return;
        }
        reject(new Error(`TTS 请求失败：${resp.statusCode}`));
      },
      fail(error) {
        reject(new Error(error.errMsg || "TTS 网络请求失败"));
      }
    });
  });
}

function playWavBuffer(buffer) {
  return new Promise((resolve, reject) => {
    const fs = wx.getFileSystemManager();
    const filePath = `${wx.env.USER_DATA_PATH}/anti_fraud_tts_${Date.now()}.wav`;
    fs.writeFile({
      filePath,
      data: buffer,
      success() {
        if (audioContext) {
          audioContext.stop();
          audioContext.destroy();
        }
        audioContext = wx.createInnerAudioContext();
        audioContext.src = filePath;
        audioContext.onEnded(() => resolve());
        audioContext.onStop(() => resolve());
        audioContext.onError((error) => reject(new Error(error.errMsg || "音频播放失败")));
        audioContext.play();
      },
      fail(error) {
        reject(new Error(error.errMsg || "写入音频失败"));
      }
    });
  });
}

async function speakWithKokoro(text, sid = 3) {
  const buffer = await requestTtsAudio(text, sid);
  await playWavBuffer(buffer);
}

function stopPlayback() {
  if (!audioContext) return;
  try {
    audioContext.stop();
    audioContext.destroy();
  } catch (error) {
    // Ignore stale audio contexts.
  }
  audioContext = null;
}

async function warmupTts(sid = 3) {
  try {
    await api.post("/game/simulation/tts/warmup", {
      text: "你好。",
      sid,
      speed: 1.0
    });
  } catch (error) {
    // Warmup is only an optimization; playback can still request TTS later.
  }
}

function transcribeAudioFile(tempFilePath, options = {}) {
  const audioFormat = options.audioFormat || "wav";
  const sampleRate = options.sampleRate || 16000;
  return new Promise((resolve, reject) => {
    wx.getFileSystemManager().readFile({
      filePath: tempFilePath,
      encoding: "base64",
      success: async (file) => {
        try {
          const data = await api.post("/game/simulation/asr", {
            audio_base64: file.data,
            sample_rate: sampleRate,
            audio_format: audioFormat
          });
          resolve(data);
        } catch (error) {
          reject(error);
        }
      },
      fail(error) {
        reject(new Error(error.errMsg || "读取录音失败"));
      }
    });
  });
}

function transcribePcmFile(tempFilePath) {
  return transcribeAudioFile(tempFilePath, { audioFormat: "pcm_s16le", sampleRate: 16000 });
}

module.exports = {
  ensureRecordPermission,
  speakWithKokoro,
  stopPlayback,
  transcribeAudioFile,
  warmupTts,
  transcribePcmFile
};
