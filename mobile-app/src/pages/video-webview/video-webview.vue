<template>
  <view class="video-webview-page">
    <web-view v-if="sourceUrl" :src="sourceUrl" />
    <view v-else class="video-webview-empty">官方链接暂不可用</view>
  </view>
</template>

<script setup>
import { ref } from "vue";
import { onLoad } from "@dcloudio/uni-app";

const sourceUrl = ref("");

onLoad((options = {}) => {
  let value = String(options.url || "").trim();
  try {
    value = decodeURIComponent(value);
  } catch {}
  if (/^https?:\/\//i.test(value)) sourceUrl.value = value;
});
</script>

<style scoped>
.video-webview-page {
  width: 100%;
  min-height: 100vh;
  background: #ffffff;
}

.video-webview-empty {
  padding: 48rpx 32rpx;
  color: #777777;
  font-size: 28rpx;
  text-align: center;
}
</style>
