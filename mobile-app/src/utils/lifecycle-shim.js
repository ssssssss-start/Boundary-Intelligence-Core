import { onBeforeUnmount, onMounted } from "vue";

export function onLoad(callback) {
  onMounted(() => callback && callback({}));
}

export function onShow(callback) {
  onMounted(() => callback && callback());
}

export function onUnload(callback) {
  onBeforeUnmount(() => callback && callback());
}
