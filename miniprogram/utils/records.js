function currentUserId() {
  const app = getApp();
  return (app.globalData && app.globalData.userId) || "demo_user";
}

function storageKey(type) {
  return `antiFraudMini:${currentUserId()}:${type}`;
}

function readRecords(type) {
  try {
    const value = wx.getStorageSync(storageKey(type));
    return Array.isArray(value) ? value : [];
  } catch (error) {
    return [];
  }
}

function writeRecords(type, records) {
  wx.setStorageSync(storageKey(type), Array.isArray(records) ? records : []);
}

function addRecord(type, record, limit = 50) {
  const item = {
    id: `${type}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    time: new Date().toISOString(),
    ...record
  };
  const records = [item].concat(readRecords(type)).slice(0, limit);
  writeRecords(type, records);
  return item;
}

function clearRecords(type) {
  wx.removeStorageSync(storageKey(type));
}

module.exports = {
  addRecord,
  clearRecords,
  readRecords,
  writeRecords
};
