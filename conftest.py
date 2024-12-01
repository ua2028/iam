# conftest.py
import re
import os
import uuid
import shutil
import pytest
from time import sleep
from loguru import logger
from dotenv import load_dotenv
load_dotenv()

from utils.aws_handler import AWSHandler

# create an admin aws handler
admin_aws_handler = AWSHandler()
try:
    admin_aws_handler.validate_credentials()
    admin_aws_handler.load_policies_from_files()
except Exception as e:
    logger.info(f"AWS credentials error {str(e)}")


@pytest.fixture(scope="function")
def admin_aws_client(request):
    return admin_aws_handler


@pytest.fixture(scope="function")
def user_aws_client(request):
    logger.info("Create a test user")
    test_user_name = f"user-test-{uuid.uuid4()}"
    pytest.test_data['users'].append(test_user_name)
    admin_aws_handler.create_iam_user(test_user_name)
    credentials = admin_aws_handler.create_iam_user_credentials(test_user_name)
    access_key = credentials["AccessKeyId"]
    secret_key = credentials["SecretAccessKey"]
    logger.info(f"---------------------- access_key: {access_key}")
    logger.info(f"---------------------- secret_key: {secret_key}")
    aws_handler = AWSHandler(test_user_name, access_key, secret_key, True )
    # aws_handler.name = test_user_name
    # adding sleep because of flaky issue of getting from AWS error of invalid token when starting
    # actions in the test
    sleep(5)
    return aws_handler


def pytest_configure():
    pytest.is_local = False
    pytest.is_stage = False
    pytest.test_data = {
        "policies": [],
        "users": [],
        "groups": []
    }



@pytest.fixture(scope="session", autouse=True)
def setup(request):
    logger.info("!!!!!!!!! Do setup here if needed !!!!!!!!!")
    yield

    def session_finish():
        logger.info("****************************************************************************")
        logger.info("****************************************************************************")
        logger.info("*************************  END OF TEST SESSION  ****************************")
        logger.info("****************************************************************************")
        logger.info("****************************************************************************")
        logger.info("Perform teardown actions after all tests are done")
        users = pytest.test_data.get('users', False)
        logger.info(f"users to delete: {users}")
        if len(users) > 0:
            for test_user_name in users:
                logger.info(f"Found a test user name '{test_user_name}', deleting it")
                admin_aws_handler.delete_iam_user_and_all_resources_by_user_name(test_user_name)

        policies = pytest.test_data.get('policies', False)
        logger.info(f"Policies to delete: {policies}")
        if len(policies) > 0:
            for policy_name in policies:
                logger.info(f"Found a test policy '{policy_name}', deleting it")
                admin_aws_handler.remove_policy_by_name(policy_name)

        groups = pytest.test_data.get('groups', False)

        logger.info(f"Policies to delete: {policies}")
        if len(groups) > 0:
            for group_name in groups:
                logger.info(f"Found a group with name: '{group_name}', deleting it")
                admin_aws_handler.delete_group(group_name)


    request.addfinalizer(session_finish)


def delete_pycache():
    logger.info("delete all pycache")
    for root, dirs, files in os.walk('.'):
        for dir_name in dirs:
            if dir_name == "__pycache__":
                cache_dir = os.path.join(root, dir_name)
                try:
                    shutil.rmtree(cache_dir)
                except Exception as e:
                  logger.info(f"delete_pycache err: {str(e)}")


def pytest_sessionstart(session):
    # Get the command-line arguments passed to pytest
    args = session.config.invocation_params.args
    logger.info(f"Pytest called with arguments: {args}")

    #Make sure to delete any pycache
    delete_pycache()

