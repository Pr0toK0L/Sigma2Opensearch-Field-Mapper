import yaml
import json
import sys
import os

def convert_yaml_to_json(input_file, default_category="window"):
    # Đọc nội dung từ file YAML
    with open(input_file, "r", encoding="utf-8") as f:
        try:
            rule = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"Lỗi đọc YAML: {e}")
            return

    # Thêm category nếu chưa có
    if "category" not in rule:
        rule["category"] = default_category
        print(f"Đã thêm 'category: {default_category}' vào rule.")

    # Ghi ra file JSON
    output_file = os.path.splitext(input_file)[0] + ".json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(rule, f, indent=2)
    
    print(f"Đã chuyển đổi {input_file} ➝ {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Cách dùng: python ruleToJson.py <tên_file_yaml>")
        sys.exit(1)

    input_file = sys.argv[1]
    convert_yaml_to_json(input_file)
