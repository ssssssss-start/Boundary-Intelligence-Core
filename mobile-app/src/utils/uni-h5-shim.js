function parseStorage(value) {
  if (value === null || value === undefined) return "";
  try {
    return JSON.parse(value);
  } catch (error) {
    return value;
  }
}

function routeFromUrl(url) {
  const clean = String(url || "/pages/chat/chat").replace(/^\//, "");
  return `#/${clean}`;
}

function showToast(title) {
  const existing = document.querySelector(".uni-h5-toast");
  if (existing) existing.remove();
  const toast = document.createElement("div");
  toast.className = "uni-h5-toast";
  toast.textContent = title;
  Object.assign(toast.style, {
    position: "fixed",
    left: "50%",
    bottom: "18vh",
    transform: "translateX(-50%)",
    maxWidth: "72vw",
    padding: "10px 14px",
    borderRadius: "999px",
    background: "rgba(0, 0, 0, 0.78)",
    color: "#fff",
    fontSize: "14px",
    zIndex: 9999,
    textAlign: "center"
  });
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 1500);
}

function installTapBridge() {
  if (window.__antiFraudTapBridgeInstalled) return;
  window.__antiFraudTapBridgeInstalled = true;
  document.addEventListener(
    "click",
    (event) => {
      if (!event.target || event.__antiFraudSyntheticTap) return;
      const tapEvent = new CustomEvent("tap", {
        bubbles: true,
        cancelable: true,
        detail: { source: "click" }
      });
      tapEvent.__antiFraudSyntheticTap = true;
      event.target.dispatchEvent(tapEvent);
    },
    true
  );
}

function request(options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeout || 30000);
  fetch(options.url, {
    method: options.method || "GET",
    headers: options.header || {},
    body: (options.method || "GET").toUpperCase() === "GET" ? undefined : JSON.stringify(options.data || {}),
    signal: controller.signal
  })
    .then(async (response) => {
      clearTimeout(timeout);
      const contentType = response.headers.get("content-type") || "";
      const data = contentType.includes("application/json") ? await response.json() : await response.text();
      options.success && options.success({ statusCode: response.status, data });
    })
    .catch((error) => {
      clearTimeout(timeout);
      options.fail && options.fail({ errMsg: error.message || "request failed" });
    });
}

export function installUniH5Shim() {
  if (globalThis.uni) return;
  installTapBridge();
  globalThis.uni = {
    getStorageSync(key) {
      return parseStorage(localStorage.getItem(key));
    },
    setStorageSync(key, value) {
      localStorage.setItem(key, JSON.stringify(value));
    },
    removeStorageSync(key) {
      localStorage.removeItem(key);
    },
    request,
    showToast(options = {}) {
      showToast(options.title || "");
    },
    navigateTo(options = {}) {
      location.hash = routeFromUrl(options.url);
      options.success && options.success();
    },
    redirectTo(options = {}) {
      location.hash = routeFromUrl(options.url);
      options.success && options.success();
    },
    navigateBack(options = {}) {
      if (history.length > 1) {
        history.back();
        options.success && options.success();
      } else {
        location.hash = "#/pages/chat/chat";
        options.fail && options.fail();
      }
    },
    getSystemInfoSync() {
      return {
        statusBarHeight: 0,
        windowWidth: window.innerWidth,
        windowHeight: window.innerHeight
      };
    },
    getRecorderManager() {
      return null;
    }
  };
}
