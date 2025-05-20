import os
import yaml
import json
import requests
import uuid
from datetime import date
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

username = 'admin'
password = 'BkcsSiem01'
node_ip = '192.168.39.20'
port = 9200
url = f'https://{node_ip}:{port}/_plugins/_security_analytics/rules?category=apache_access' # category=linux/windows/apache_access

headers = {
    'Content-Type': 'application/json'
}

# Load file mapping
mapping_file_path = 'D:\\SECURITY documents\\Opensearch\\SigmaToAuditbeatFields.txt'

def load_field_mapping(file_path):
    field_mapping = {}
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and ':' in line:
                sigma_field, auditbeat_field = line.split(':', 1)
                field_mapping[sigma_field.strip()] = auditbeat_field.strip()
    return field_mapping

field_mapping = load_field_mapping(mapping_file_path)

# Convert date
def convert_dates(obj):
    if isinstance(obj, dict):
        return {key: convert_dates(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_dates(item) for item in obj]
    elif isinstance(obj, date):
        return obj.isoformat()
    else:
        return obj

# Add date field
def add_date_field(yaml_content):
    if 'date' not in yaml_content:
        yaml_content['date'] = date.today().isoformat()
    return yaml_content

# Mapping detection fields
def map_detection_fields(detection, field_mapping):
    if isinstance(detection, dict):
        new_detection = {}
        for key, value in detection.items():
            if '|' in key:
                field_name, op = key.split('|', 1)
                mapped_field = field_mapping.get(field_name.strip(), field_name.strip())
                new_key = f"{mapped_field}|{op.strip()}"
            else:
                mapped_field = field_mapping.get(key.strip(), key.strip())
                new_key = mapped_field

            new_detection[new_key] = map_detection_fields(value, field_mapping)
        return new_detection
    elif isinstance(detection, list):
        return [map_detection_fields(item, field_mapping) for item in detection]
    else:
        return detection

# Rule folder path
rule_folder = 'D:\\SECURITY documents\\Opensearch\\'

for filename in os.listdir(rule_folder):
    if filename.endswith('.yaml') or filename.endswith('.yml'):
        try:
            with open(os.path.join(rule_folder, filename), 'r', encoding='utf-8') as yaml_file:
                yaml_content = yaml.safe_load(yaml_file)

            # add UUID if not exist
            yaml_content['id'] = str(uuid.uuid4())

            # add date field if not exist
            yaml_content = add_date_field(yaml_content)

            yaml_content = convert_dates(yaml_content)

            if 'detection' in yaml_content:
                yaml_content['detection'] = map_detection_fields(yaml_content['detection'], field_mapping)

            # convert rule field to JSON if it is a dictionary
            if 'rule' in yaml_content and isinstance(yaml_content['rule'], dict):
                yaml_content['rule'] = json.dumps(yaml_content['rule'])

            json_payload = json.dumps(yaml_content)

            # request to upload the rule
            response = requests.post(
                url,
                headers=headers,
                data=json_payload,
                auth=(username, password),
                verify=False
            )

            if response.status_code in [200, 201]:
                print(f"Upload successfully: {filename}")
            else:
                print(f"Upload failed: {filename} ➔ Error {response.status_code}: {response.text}")

        except Exception as e:
            print(f"Upload failed: {filename} ➔ Exception: {str(e)}")
