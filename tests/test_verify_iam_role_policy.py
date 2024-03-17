import json
import os
import unittest
from src.verify_iam_role_policy import verify_iam_role_policy


class TestJsonValidator(unittest.TestCase):
    """Test cases for the JSON validator"""

    @classmethod
    def setUpClass(cls):
        cls.json_files_dir = os.path.join(os.path.dirname(__file__), 'json_files')

    def read_json_from_file(self, filename):
        json_file_path = os.path.join(self.json_files_dir, filename)
        try:
            with open(json_file_path, 'r') as file:
                return json.load(file)
        except json.JSONDecodeError:
            return None

    def test_valid_json_with_single_asterisk(self):
        json_data = self.read_json_from_file('test_valid_json_with_single_asterisk.json')
        self.assertFalse(verify_iam_role_policy(json_data))

    def test_valid_json_with_double_asterisk(self):
        json_data = self.read_json_from_file('test_valid_json_with_double_asterisk.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_valid_json_without_single_asterisk(self):
        json_data = self.read_json_from_file('test_valid_json_without_single_asterisk.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_invalid_json_missing_resource_field(self):
        json_data = self.read_json_from_file('test_invalid_json_missing_resource_field.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_policy_name_with_invalid_pattern(self):
        json_data = self.read_json_from_file('test_policy_name_with_invalid_pattern.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_invalid_json_policy_document(self):
        json_data = self.read_json_from_file('test_invalid_json_policy_document.json')
        with self.assertRaises(ValueError) as error:
            verify_iam_role_policy(json_data)

        self.assertEqual(str(error.exception), "PolicyDocument must be a valid JSON object")

    def test_invalid_json_with_invalid_json_syntax(self):
        json_data = self.read_json_from_file('test_invalid_json_with_invalid_json_syntax.json')
        with self.assertRaises(ValueError) as error:
            verify_iam_role_policy(json_data)

        self.assertEqual(str(error.exception), "Invalid JSON format")

    def test_invalid_json_with_invalid_structure(self):
        json_data = self.read_json_from_file('test_policy_name_with_invalid_type.json')
        with self.assertRaises(ValueError) as error:
            verify_iam_role_policy(json_data)

        self.assertEqual(str(error.exception),
                         "PolicyName must contain only alphanumeric characters and/or the following: +=,.@-")


    def test_missing_policy_document(self):
        json_data = self.read_json_from_file('test_missing_policy_document.json')
        with self.assertRaises(ValueError) as error:
            verify_iam_role_policy(json_data)

        self.assertEqual(str(error.exception), "Missing PolicyDocument in JSON data")

    def test_policy_name_exceeding_maximum_length(self):
        json_data = self.read_json_from_file('test_policy_name_exceeding_maximum_length.json')
        with self.assertRaises(ValueError) as error:
            verify_iam_role_policy(json_data)

        self.assertEqual(str(error.exception), "PolicyName must be between 1 and 128 characters long")

    def test_policy_name_with_invalid_characters(self):
        json_data = self.read_json_from_file('test_policy_name_with_invalid_characters.json')
        with self.assertRaises(ValueError) as error:
            verify_iam_role_policy(json_data)

        self.assertEqual(str(error.exception),
                         "PolicyName must contain only alphanumeric characters and/or the following: +=,.@-")

    def test_policy_name_with_maximum_length(self):
        json_data = self.read_json_from_file('test_policy_name_with_maximum_length.json')
        with self.assertRaises(ValueError) as error:
            verify_iam_role_policy(json_data)

        self.assertEqual(str(error.exception), "PolicyName must be between 1 and 128 characters long")

    def test_empty_policy_document(self):
        json_data = self.read_json_from_file('test_empty_policy_document.json')
        self.assertTrue(verify_iam_role_policy(json_data))

    def test_valid_json_with_specific_permissions(self):
        json_data = self.read_json_from_file('test_valid_json_with_specific_permissions.json')
        self.assertTrue(verify_iam_role_policy(json_data))


if __name__ == "__main__":
    unittest.main()
