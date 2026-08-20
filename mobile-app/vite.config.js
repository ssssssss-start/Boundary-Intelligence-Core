import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

const root = path.dirname(fileURLToPath(import.meta.url));
const rpxRatio = 0.5;

function rpxToPxPlugin() {
  return {
    postcssPlugin: "anti-fraud-rpx-to-px",
    Declaration(decl) {
      if (!decl.value || !decl.value.includes("rpx")) return;
      decl.value = decl.value.replace(/(-?\d*\.?\d+)rpx/g, (_, value) => `${Number(value) * rpxRatio}px`);
    }
  };
}

rpxToPxPlugin.postcss = true;

export default defineConfig({
  plugins: [
    vue({
      template: {
        compilerOptions: {
          isCustomElement: (tag) => ["view", "scroll-view", "text", "picker"].includes(tag)
        }
      }
    })
  ],
  resolve: {
    alias: {
      "@dcloudio/uni-app": path.resolve(root, "src/utils/lifecycle-shim.js")
    }
  },
  css: {
    postcss: {
      plugins: [rpxToPxPlugin()]
    }
  }
});
