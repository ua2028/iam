
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
docker run --rm -it -v "$(pwd)/allure-report:/app/allure-report" -v "$(pwd)/allure-results:/app/allure-results" -e AWS_ACCESS_KEY_ID=ACCESS_KEY -e AWS_SECRET_ACCESS_KEY=SECRET_KEY --network="host" test-runner

### Explanation:
--rm: Automatically removes the container after it exits.
-it: Runs the container interactively, useful for debugging.
-e AWS_ACCESS_KEY_ID and -e AWS_SECRET_ACCESS_KEY: Pass environment variables to the container.
-v "$(pwd)/allure-report:/app/allure-report": Mounts a local directory to the container's /app/allure-report directory so the generated report can be accessed on your host machine.



first run test for UI login to collect the api key and set it
```commandline
pytest -s -k "TEST_NAME"

```
