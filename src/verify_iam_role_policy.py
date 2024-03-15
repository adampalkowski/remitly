import json


def verify_iam_role_policy(json_data):
    try:
        statement = json_data.get("PolicyDocument", {}).get("Statement", [])
        for statement_item in statement:
            resource = statement_item.get("Resource")
            if resource == "*":
                return False
        return True
    except AttributeError:
        return True



