import sys
import json
import requests

host = "192.168.39.20"
port = 9200
username = "admin"
password = "BkcsSiem01"

file_path = sys.argv[1]

# Tạo rule_id từ tên file (bạn có thể chỉnh sửa nếu cần)
import os
rule_id = os.path.splitext(os.path.basename(file_path))[0].replace(" ", "_")

with open(file_path, "r") as f:
    rule_data = json.load(f)

url = f"https://{host}:{port}/_plugins/_security_analytics/rules/{rule_id}"

response = requests.put(
    url,
    auth=(username, password),
    headers={"Content-Type": "application/json"},
    json=rule_data,
    verify=False
)

if response.status_code in [200, 201]:
    print("✅ Rule upload thành công!")
    print("📄 Rule ID:", rule_id)
else:
    print("❌ Upload thất bại!")
    print("🔧 Status:", response.status_code)
    print(response.text)
