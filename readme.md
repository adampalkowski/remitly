# Instructions for Running the Program and Tests

# Instructions for Running the Program and Tests

To run the program, you need to have Python 3.9 installed on your machine. You can download it from the [official website](https://www.python.org/downloads/).

After installing Python, download the repository by running:


"git clone https://github.com/adampalkowski/remitly"


The `remitly/src` directory contains the verifying function `verify_iam_role_policy.py`.

To run the function, you should be in the `remitly` directory and run the following command:


"python src/verify_iam_role_policy.py <your_test_file_json>.json"

for example:
"python src/verify_iam_role_policy.py sample_json.json"
or 
"python src/verify_iam_role_policy.py tests/json_files/test_policy_name_exceeding_maximum_length.json"


To run the function manually, navigate to `remitly/src/verify_iam_role_policy.py` and click the green arrow on the left of `__main__` at the bottom.

The `remitly/tests` directory contains unit tests for the method. 

To run the tests, you should be in the `remitly` directory and run the following command:



To run the tests manually, navigate to `remitly/tests/test_verify_iam_role_policy.py` and click the green arrow on the left of `__main__` at the bottom.

The `remitly/tests/json_files` directory contains sample JSON files for testing the program.
