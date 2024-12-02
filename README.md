
# QA AUTOMATION

This project uses Poetry for dependency management. 
The following instructions guide you through the setup process and running the tests.

## Prerequisites

- Python 3.11
- [Poetry](https://python-poetry.org/docs/)

### Install Poetry

install Poetry by following the instructions on the [official website](https://python-poetry.org/docs/#installation).

# Setup

### Activate the Poetry environment
poetry env use python3.11

### Install dependencies
poetry install --no-root

### Start shell
poetry shell

### Set your AWS credetials as a profile
Open  
```commandline
~/.aws/credentials
```

Paste your credentials using this format to create an AWS profile:
```commandline
[qa]
aws_access_key_id=YOUR_ACCESS_KEY
aws_secret_access_key=YOUR_SECRET_KEY
```

or set them as ENV variables:
```commandline
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
```

### Run test:
```commandline
pytest -s --alluredir=allure-results
```

### To create requirements.txt:
If you need to update requirements.txt
```commandline
poetry export -f requirements.txt --output requirements.txt
```

### Run test locally and generate report

```commandline
pytest -s --html=report.html
```


# Run docker locally
### Build
```shell
docker build -t test-runner .
```

### Run
```shell
docker run -e AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY -e AWS_SECRET_ACCESS_KEY=YOUR_SECRET --name=runner --network="host" test-runner
```

### Run with docker compose:
```commandline
export AWS_SECRET_ACCESS_KEY=YOUR_ACCESS_KEY AWS_SECRET_ACCESS_KEY=YOUR_SECRET && docker compose up --build
```