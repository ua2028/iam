
# QA AUTOMATION

This project uses Poetry for dependency management. 
The following instructions guide you through the setup process and running the tests.

## Prerequisites

- Python 3.11
- [Poetry](https://python-poetry.org/docs/)

### Install Poetry

install Poetry by following the instructions on the [official website](https://python-poetry.org/docs/#installation).

### Setup

# Activate the Poetry environment
poetry env use python3.11

# Install dependencies
poetry install --no-root

# Start shell
poetry shell

# Set your AWS credetials as a profile
Open  ~/.aws/credentials

Use this format:
[qa]
aws_access_key_id=YOUR_ACCESS_KEY
aws_secret_access_key=YOUR_SECRET_KEY

# Run test:
pytest -s --alluredir=allure-results

# To create requirements.txt:
poetry export -f requirements.txt --output requirements.txt

### Run docker locally

docker build -t test-runner .
docker run -e AWS_ACCESS_KEY_ID=ACCESS_KEY -e AWS_SECRET_ACCESS_KEY=SECRET_KEY --name=runner --network="host" test-runner

### Explanation:
-e AWS_ACCESS_KEY_ID and -e AWS_SECRET_ACCESS_KEY: Pass environment variables to the container.



first run test for UI login to collect the api key and set it
```commandline
pytest -s -k "TEST_NAME"

```
