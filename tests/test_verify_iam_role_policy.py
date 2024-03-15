import json
import os
import unittest
from src.verify_iam_role_policy import verify_iam_role_policy

class TestJsonValidator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.json_files_dir = os.path.join(os.path.dirname(__file__), 'json_files')

    def read_json_from_file(self, filename):
        if not filename.endswith('.json'):
            raise ValueError("File is not a JSON file")

        json_file_path = os.path.join(self.json_files_dir, filename)
        try:
            with open(json_file_path, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            return None


    def test_valid_json_with_single_asterisk(self):
        json_data = self.read_json_from_file('test_valid_json_with_single_asterisk.json')
        self.assertFalse(verify_iam_role_policy(json_data))

    def test_valid_json_without_single_asterisk(self):
        json_data = self.read_json_from_file('test_valid_json_without_single_asterisk.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_invalid_json_missing_resource_field(self):
        json_data = self.read_json_from_file('test_invalid_json_missing_resource_field.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_invalid_json_policy_document(self):
        json_data = self.read_json_from_file('test_invalid_json_policy_document.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_invalid_json_with_invalid_json_syntax(self):
        json_data = self.read_json_from_file('test_invalid_json_with_invalid_json_syntax.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_invalid_json_with_invalid_structure(self):
        json_data = self.read_json_from_file('test_invalid_json_with_invalid_structure.json')
        self.assertFalse(verify_iam_role_policy(json_data))

    def test_invalid_json_with_single_asterisk(self):
        json_data = self.read_json_from_file('test_invalid_json_with_single_asterisk.json')
        self.assertFalse(verify_iam_role_policy(json_data))

    def test_missing_policy_document(self):
        json_data = self.read_json_from_file('test_missing_policy_document.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_policy_name_exceeding_maximum_length(self):
        json_data = self.read_json_from_file('test_policy_name_exceeding_maximum_length.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_policy_name_with_invalid_characters(self):
        json_data = self.read_json_from_file('test_policy_name_with_invalid_characters.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_policy_name_with_maximum_length(self):
        json_data = self.read_json_from_file('test_policy_name_with_maximum_length.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_empty_policy_document(self):
        json_data = self.read_json_from_file('test_empty_policy_document.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_valid_json_with_specific_permissions(self):
        json_data = self.read_json_from_file('test_valid_json_with_specific_permissions.json')
        self.assertTrue(verify_iam_role_policy(json_data))
