import yaml

# Load field mapping from file
def load_field_mapping(file_path):
    field_mapping = {}
    with open(file_path, 'r') as file:
        for line in file.readlines():
            sigma_field, auditbeat_field = line.strip().split(': ')
            field_mapping[sigma_field] = auditbeat_field
    return field_mapping

# Map Sigma fields to Auditbeat fields
def map_fields(sigma_rule, field_mapping):
    for key, value in field_mapping.items():
        if key in sigma_rule['detection']['selection']:
            sigma_rule['detection']['selection'][value] = sigma_rule['detection']['selection'].pop(key)
    return sigma_rule

# Convert selection and condition to DQL query format
def generate_dql_query(sigma_rule):
    query_parts = []
    selection = sigma_rule['detection']['selection']
    
    for field, value in selection.items():
        # Handle contains (convert to "is one of")
        if isinstance(value, list):
            query_part = f"({field}: is one of {' '.join(value)})"
        # Handle endswith (append '*' to value)
        elif isinstance(value, str) and value.endswith('*'):
            query_part = f"({field}: {value})"
        # Handle startswith (prepend '*' to value)
        elif isinstance(value, str) and value.startswith('*'):
            query_part = f"({field}: {value})"
        # Default term query
        else:
            query_part = f"({field}: {value})"
        
        query_parts.append(query_part)
    
    # Join all parts with 'and'
    return ' and '.join(query_parts)

# Convert Sigma to DQL
def convert_sigma_to_dql(sigma_file, field_mapping_file):
    # Load field mapping from the provided file
    field_mapping = load_field_mapping(field_mapping_file)

    with open(sigma_file, 'r') as file:
        sigma_rule = yaml.safe_load(file)
        
        # Map Sigma fields to Auditbeat
        sigma_rule = map_fields(sigma_rule, field_mapping)

        # Generate DQL query
        dql_query = generate_dql_query(sigma_rule)

        return dql_query
# Example usage
sigma_file = 'D:\\SECURITY documents\\Opensearch\\Decode Base64 Encoded Text.yaml'
field_mapping_file = 'D:\\SECURITY documents\\Opensearch\\SigmaToAuditbeatFields.txt'
dql_query = convert_sigma_to_dql(sigma_file, field_mapping_file)
print(dql_query)
