const DEFAULT_BASE_URL = "http://127.0.0.1:8001";
const BASE_URL_KEY = "antiFraudMobileBaseUrl";

export function normalizeBaseUrl(value) {
  const raw = String(value || DEFAULT_BASE_URL).trim();
  return raw.replace(/\/+$/, "") || DEFAULT_BASE_URL;
}

export function getBaseUrl() {
  return normalizeBaseUrl(uni.getStorageSync(BASE_URL_KEY) || DEFAULT_BASE_URL);
}

export function setBaseUrl(value) {
  const next = normalizeBaseUrl(value);
  uni.setStorageSync(BASE_URL_KEY, next);
  return next;
}

export function request(path, options = {}) {
  const url = `${getBaseUrl()}${path.startsWith("/") ? path : `/${path}`}`;
  return new Promise((resolve, reject) => {
    uni.request({
      url,
      method: options.method || "GET",
      data: options.data || {},
      timeout: options.timeout || 30000,
      header: {
        "Content-Type": "application/json",
        ...(options.header || {})
      },
      success(response) {
        const statusCode = Number(response.statusCode || 0);
        if (statusCode >= 200 && statusCode < 300) {
          resolve(response.data);
          return;
        }
        const data = response.data || {};
        reject(new Error(data.detail || data.message || `请求失败：${statusCode}`));
      },
      fail(error) {
        reject(new Error(`后端连接失败：${error.errMsg || "网络请求失败"}。请确认查询服务已启动，并配置为手机可访问的后端地址。`));
      }
    });
  });
}

export function get(path, data = {}) {
  const query = Object.keys(data)
    .filter((key) => data[key] !== undefined && data[key] !== null && data[key] !== "")
    .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(data[key])}`)
    .join("&");
  return request(`${path}${query ? `?${query}` : ""}`, { method: "GET" });
}

export function post(path, data = {}, options = {}) {
  return request(path, { ...options, method: "POST", data });
}
