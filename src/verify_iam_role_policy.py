import json
import re
import sys


def verify_iam_role_policy(json_data):
    """Verifies if any Resource field in the input IAM policy JSON contains a single asterisk.

    Args:
        json_data (str or dict): The IAM policy JSON data, either as a string or a dictionary.

    Returns:
        bool: True if all Resource fields are valid, False if any Resource field contains a single asterisk.
    """
    if isinstance(json_data, str):
        raise ValueError("Invalid JSON format")

    pattern = r"[\w+=,.@-]+"  # The pattern to be checked

    policy_document = json_data.get("PolicyDocument")
    policy_name = json_data.get("PolicyName")

    if not policy_document:
        raise ValueError("Missing PolicyDocument in JSON data")
    if not policy_name:
        raise ValueError("Missing PolicyName in JSON data")
    if not isinstance(policy_name, str) or not re.match(pattern, policy_name):
        raise ValueError("PolicyName must contain only alphanumeric characters and/or the following: +=,.@-")
    if len(policy_name) > 128 or len(policy_name) < 1:
        raise ValueError("PolicyName must be between 1 and 128 characters long")
    if not isinstance(policy_document, dict):
        raise ValueError("PolicyDocument must be a valid JSON object")

    statements = policy_document.get("Statement")
    if not statements:
        return True

    for statement in statements:
        resource = statement.get("Resource")
        if isinstance(resource, str) and resource == "*":
            return False

    return True


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python verify_iam_role_policy.py <json_file_path>")
        sys.exit(1)

    json_file_path = sys.argv[1]

    try:
        with open(json_file_path, 'r') as file:
            json_data = json.load(file)
    except FileNotFoundError:
        print(f"Error: File '{json_file_path}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in '{json_file_path}'.")
        sys.exit(1)

    result = verify_iam_role_policy(json_data)
    if result:
        print("All Resource fields are valid. No single asterisk found.")
    else:
        print("At least one Resource field contains a single asterisk.")
