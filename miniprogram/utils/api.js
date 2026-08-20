const DEFAULT_BASE_URL = "http://127.0.0.1:8001";

function normalizeBaseUrl(value) {
  const raw = String(value || DEFAULT_BASE_URL).trim();
  return raw.replace(/\/+$/, "") || DEFAULT_BASE_URL;
}

function appBaseUrl() {
  const app = getApp();
  return normalizeBaseUrl((app.globalData && app.globalData.baseUrl) || DEFAULT_BASE_URL);
}

function request(path, options = {}) {
  const url = `${appBaseUrl()}${path.startsWith("/") ? path : `/${path}`}`;
  const method = options.method || "GET";
  const data = options.data || {};
  return new Promise((resolve, reject) => {
    wx.request({
      url,
      method,
      data,
      timeout: options.timeout || 30000,
      header: {
        "Content-Type": "application/json",
        ...(options.header || {})
      },
      success(resp) {
        if (resp.statusCode >= 200 && resp.statusCode < 300) {
          resolve(resp.data);
          return;
        }
        const detail = resp.data && (resp.data.detail || resp.data.message);
        reject(new Error(detail || `请求失败：${resp.statusCode}`));
      },
      fail(error) {
        const reason = error.errMsg || "网络请求失败";
        reject(new Error(`后端连接失败：${reason}。请确认 8001 查询服务已启动，并且开发者工具已开启“不校验合法域名”。`));
      }
    });
  });
}

function get(path, data) {
  const query = data ? `?${Object.keys(data)
    .filter((key) => data[key] !== undefined && data[key] !== null && data[key] !== "")
    .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(data[key])}`)
    .join("&")}` : "";
  return request(`${path}${query}`, { method: "GET" });
}

function post(path, data) {
  return request(path, { method: "POST", data });
}

module.exports = {
  DEFAULT_BASE_URL,
  normalizeBaseUrl,
  appBaseUrl,
  request,
  get,
  post
};
