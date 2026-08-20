import { post } from "./api";

function readFileBase64(filePath) {
  return new Promise((resolve, reject) => {
    if (uni.getFileSystemManager) {
      uni.getFileSystemManager().readFile({
        filePath,
        encoding: "base64",
        success: (file) => resolve(file.data),
        fail: (error) => reject(new Error(error.errMsg || "读取录音失败"))
      });
      return;
    }
    if (typeof plus !== "undefined" && plus.io) {
      plus.io.resolveLocalFileSystemURL(
        filePath,
        (entry) => {
          entry.file((file) => {
            const reader = new plus.io.FileReader();
            reader.onloadend = (event) => {
              const result = String(event.target.result || "");
              resolve(result.includes(",") ? result.split(",").pop() : result);
            };
            reader.onerror = () => reject(new Error("读取录音失败"));
            reader.readAsDataURL(file);
          }, () => reject(new Error("读取录音失败")));
        },
        () => reject(new Error("读取录音失败"))
      );
      return;
    }
    reject(new Error("当前平台暂不支持读取录音文件"));
  });
}

export function recorderManager() {
  return uni.getRecorderManager ? uni.getRecorderManager() : null;
}

export async function transcribeAudioFile(filePath, options = {}) {
  const audioBase64 = await readFileBase64(filePath);
  return post("/game/simulation/asr", {
    audio_base64: audioBase64,
    sample_rate: options.sampleRate || 16000,
    audio_format: options.audioFormat || "wav"
  });
}
