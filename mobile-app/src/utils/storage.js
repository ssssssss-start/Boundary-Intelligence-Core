export function currentUserId() {
  return String(uni.getStorageSync("antiFraudMobileUserId") || "demo_user").trim() || "demo_user";
}

export function scopedKey(type) {
  return `antiFraudMobile:${currentUserId()}:${type}`;
}

export function readList(type) {
  const value = uni.getStorageSync(scopedKey(type));
  return Array.isArray(value) ? value : [];
}

export function writeList(type, value) {
  uni.setStorageSync(scopedKey(type), Array.isArray(value) ? value : []);
}

export function addRecord(type, record, limit = 50) {
  const item = {
    id: `${type}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    time: new Date().toISOString(),
    ...record
  };
  writeList(type, [item].concat(readList(type)).slice(0, limit));
  return item;
}
