import { createApp as createVueApp, createSSRApp } from "vue";
import { installUniH5Shim } from "./utils/uni-h5-shim";
import App from "./App.vue";

export function createApp() {
  installUniH5Shim();
  const app = createSSRApp(App);
  return { app };
}

if (typeof document !== "undefined") {
  installUniH5Shim();
  createVueApp(App).mount("#app");
}
