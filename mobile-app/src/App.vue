<template>
  <ChatPage v-if="page === 'chat'" />
  <TrainingPage v-else-if="page === 'training'" />
  <SimulationPage v-else />
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import ChatPage from "./pages/chat/chat.vue";
import TrainingPage from "./pages/training/training.vue";
import SimulationPage from "./pages/simulation/simulation.vue";

uni.setStorageSync("antiFraudMobileUserId", uni.getStorageSync("antiFraudMobileUserId") || "demo_user");

const route = ref(location.hash || "#/pages/chat/chat");
const page = computed(() => {
  if (route.value.includes("training")) return "training";
  if (route.value.includes("simulation")) return "simulation";
  return "chat";
});

function syncRoute() {
  route.value = location.hash || "#/pages/chat/chat";
}

onMounted(() => {
  if (!location.hash) location.hash = "#/pages/chat/chat";
  window.addEventListener("hashchange", syncRoute);
});

onBeforeUnmount(() => {
  window.removeEventListener("hashchange", syncRoute);
});
</script>

<style>
page {
  min-height: 100%;
  background: #ffffff;
  color: #151515;
  font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Helvetica Neue", Arial, sans-serif;
}

button {
  margin: 0;
  border: 0;
  appearance: none;
  -webkit-appearance: none;
  font: inherit;
}

button::after {
  border: 0;
}

textarea,
input {
  border: 0;
  outline: none;
  appearance: none;
  -webkit-appearance: none;
  background: transparent;
  box-shadow: none;
  font: inherit;
  resize: none;
}

view,
scroll-view,
text,
picker {
  display: block;
  box-sizing: border-box;
}

scroll-view {
  overflow: auto;
}

html,
body {
  width: 100%;
  height: 100%;
  margin: 0;
  background: #ffffff;
  overflow: hidden;
}

#app {
  min-height: 100vh;
}
</style>
