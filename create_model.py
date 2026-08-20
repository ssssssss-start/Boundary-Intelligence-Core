# 如果你更喜欢写代码，可以用这个方法，它会自动下载到本地
from modelscope.hub.snapshot_download import snapshot_download

model_dir = snapshot_download('BAAI/bge-m3', cache_dir='/Users/sss/main/ruikang/anti_fraud_project_delivery_20260608/model')
print(f"模型已下载到: {model_dir}")