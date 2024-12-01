import uuid
import pytest
from time import sleep
from utils.aws_handler import AWSHandler

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_limiting_policy(admin_aws_client, user_aws_client):
    logger.info("Test limiting user by IAM policy")

    logger.info("Create a group")
    group_name = f"group_name-{uuid.uuid4()}"
    admin_aws_client.create_group(group_name)
    pytest.test_data["groups"].append(group_name)

    logger.info(f"Creating policy with name containing random uuid")
    policy_name_to_use = 'limit_to_read_only_iam_policy'
    policy = admin_aws_client.policies.get(policy_name_to_use)
    policy_name = f"{policy_name_to_use}-{uuid.uuid4()}"
    # add policy to pytest to remove it later
    pytest.test_data["policies"].append(policy_name)

    logger.info(f"Add the policy to AWS")
    policy_arn = admin_aws_client.add_iam_policy(policy_name, policy)
    assert policy_arn is not None, "Policy ARN should not be None"
    logger.info(f"Policy created successfully: {policy_arn}")

    logger.info("Validate the policy is listed in the account")
    policies = admin_aws_client.get_policies()
    assert any(policy['PolicyName'] == policy_name for policy in policies), \
        f"Policy {policy_name} should be listed in the account."

    logger.info("Add policy to test user")
    admin_aws_client.attach_user_policy(user_aws_client.name, policy_arn)

    logger.info("Validate the policy is listed in the user")
    user_policies = admin_aws_client.list_attached_user_policies(user_aws_client.name)
    assert any(policy['PolicyName'] == policy_name for policy in user_policies), \
        f"Policy {policy_name} should be listed in the user list of policies."


    logger.info("Try to create a user")
    action_output = user_aws_client.create_iam_user("lolz")

    logger.info("Assert user is not allowed to create new user")
    assert "Error" in action_output, f"Key 'Error' not found, output: {action_output}"
    assert 'AccessDenied' in action_output["Error"]
    assert 'not authorized to perform: iam:CreateUser' in action_output["Error"]

    logger.info("Try to delete a user")
    # create a user with no policies to delete so it won't just fail on
    # "not authorized to perform: iam:DetachUserPolicy"
    random_name = f"delete_user-{uuid.uuid4()}"
    created_user = admin_aws_client.create_iam_user(random_name)
    pytest.test_data["users"].append(random_name)

    action_output = user_aws_client.delete_iam_user_by_user_name(random_name)

    logger.info("Assert user is not allowed to delete user")
    assert "Error" in action_output, f"Key 'Error' not found, output: {action_output}"
    assert 'AccessDenied' in action_output["Error"]
    assert 'not authorized to perform: iam:DeleteUser' in action_output["Error"]

    logger.info("Try to update a user")
    action_output = user_aws_client.update_user(random_name, "lolz")

    logger.info("Assert user is not allowed to update user ")
    assert "Error" in action_output, f"Key 'Error' not found, output: {action_output}"
    assert 'AccessDenied' in action_output["Error"]
    assert 'not authorized to perform: iam:UpdateUser' in action_output["Error"]

    logger.info("Try to attach a policy a user")
    action_output = user_aws_client.attach_user_policy(random_name, policy_arn)

    logger.info("Assert user is not allowed to attach a policy to user")
    assert "Error" in action_output, f"Key 'Error' not found, output: {action_output}"
    assert 'AccessDenied' in action_output["Error"]
    assert 'not authorized to perform: iam:AttachUserPolicy' in action_output["Error"]

    logger.info("Try to detach a policy from a user")
    action_output = user_aws_client.detach_user_policy(user_aws_client.name, policy_arn)

    logger.info("Assert user is not allowed to detach user policy")
    assert "Error" in action_output, f"Key 'Error' not found, output: {action_output}"
    assert 'AccessDenied' in action_output["Error"]
    assert 'not authorized to perform: iam:DetachUserPolicy' in action_output["Error"]

    logger.info("Try to put user policy")
    action_output = user_aws_client.put_user_inline_policy(user_aws_client.name, policy_name, policy)

    logger.info("Assert user is not allowed to put user policy")
    assert "Error" in action_output, f"Key 'Error' not found, output: {action_output}"
    assert 'AccessDenied' in action_output["Error"]
    assert 'not authorized to perform: iam:PutUserPolicy' in action_output["Error"]

    logger.info("Try to delete user policy")
    action_output = user_aws_client.delete_user_policy(user_aws_client.name, policy_name)

    logger.info("Assert user is not allowed to delete user policy")
    assert "Error" in action_output, f"Key 'Error' not found, output: {action_output}"
    assert 'AccessDenied' in action_output["Error"]
    assert 'not authorized to perform: iam:DeleteUserPolicy' in action_output["Error"]

    logger.info("Try to add user to group")
    action_output = user_aws_client.add_user_to_group(random_name, group_name)

    logger.info("Assert user is not allowed to add a user to a group")
    assert "Error" in action_output, f"Key 'Error' not found, output: {action_output}"
    assert 'AccessDenied' in action_output["Error"]
    assert 'not authorized to perform: iam:AddUserToGroup' in action_output["Error"]

    logger.info("Add user to group")
    action_output = admin_aws_client.add_user_to_group(random_name, group_name)

    logger.info("Try to remove user from a group")
    action_output = user_aws_client.remove_user_from_group(random_name, group_name)

    logger.info("Assert user is not allowed to remove a user from a group")
    assert "Error" in action_output, f"Key 'Error' not found, output: {action_output}"
    assert 'AccessDenied' in action_output["Error"]
    assert 'not authorized to perform: iam:RemoveUserFromGroup' in action_output["Error"]

    # for some reason we get this error bellow so added sleep here
    # An error occurred (AccessDenied) when calling the ListUsers operation:
    # User: arn:aws:iam::... is not authorized to perform: iam:ListUsers on resource: arn:aws:iam::...
    # because no identity-based policy allows the iam:ListUsers action
    sleep(10)

    logger.info("Try to list users")
    action_output = user_aws_client.list_users()

    logger.info("Assert user is allowed to list users")
    assert "Error" not in action_output, "Key 'Error' should not be found"
    assert all(all(key in user for key in ["UserName", "UserId", "Arn"]) for user in action_output)

    logger.info("Try to get user")
    action_output = user_aws_client.get_user(random_name)

    logger.info("Assert user is allowed to get user")
    assert "Error" not in action_output, "Key 'Error' should not be found"
    assert "UserName" in action_output, "Key 'UserName' should be found"
    assert "UserId" in action_output, "Key 'UserId' should be found"
    assert "Arn" in action_output, "Key 'Arn' should be found"

    logger.info("Create an inline policy for user")
    policy_name_list_bucket = 's3_list_bucket'
    policy_list_bucket = admin_aws_client.policies.get(policy_name_list_bucket)
    policy_list_bucket_name = f"{policy_name_list_bucket}-{uuid.uuid4()}"

    # add policy to pytest to remove it later
    pytest.test_data["policies"].append(policy_list_bucket_name)
    admin_aws_client.put_user_inline_policy(random_name, policy_list_bucket_name, policy_list_bucket)

    logger.info("Try to get user attached policy")
    action_output = user_aws_client.get_user_policy(random_name, policy_list_bucket_name)
    logger.info("Assert user is allowed to get user policy")
    assert action_output == policy_list_bucket, "Policy does not match"

    logger.info("Try to get user attached policies")
    # check for attached policies
    action_output = user_aws_client.list_attached_user_policies(user_aws_client.name)

    logger.info("Assert returned attached policies")
    assert policy_arn == action_output[0]["PolicyArn"]
    assert policy_name == action_output[0]["PolicyName"]

    logger.info("Try to get user inline policies")
    # check for user with only inline policies
    action_output = user_aws_client.list_inline_user_policies(random_name)
    logger.info("Assert policy name was returned")
    assert policy_list_bucket_name in action_output

    logger.info("Try to get user groups")
    action_output = user_aws_client.list_groups_for_user(random_name)

    logger.info("Assert group name is correct")
    assert group_name == action_output[0]["GroupName"]

    logger.info("end of test")
