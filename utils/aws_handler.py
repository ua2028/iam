import os
import json
import boto3
from time import sleep
from loguru import logger
from dotenv import load_dotenv
from botocore.exceptions import NoCredentialsError
load_dotenv()


class AWSHandler:
    def __init__(self, name="ADMIN", aws_access_key=False, aws_secret_key=False, auto_login=False):
        if not aws_access_key:
            logger.info(f"No aws_access_key, checking from ENV")
            aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        if not aws_secret_key:
            logger.info(f"No aws_secret_key, checking from ENV")
            aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        self.aws_access_key_id = aws_access_key
        self.aws_secret_access_key = aws_secret_key
        self.profile_name = os.getenv("AWS_LOCAL_PROFILE")
        self.session = None
        self.iam = None
        self.name = name
        self.path_to_policies = './policies'
        self.policies = {}
        if auto_login:
            self.validate_credentials()
            self.load_policies_from_files()

    def validate_credentials(self):
        logger.info(f"name: {self.name}, Validate AWS credentials")
        sleep(0.1)
        try:
            # Check if access keys are available in environment variables
            if self.aws_access_key_id and self.aws_secret_access_key:
                logger.info(f"name: {self.name}, self.aws_access_key_id: {self.aws_access_key_id}")
                logger.info(f"name: {self.name}, self.aws_secret_access_key: {self.aws_secret_access_key}")
                logger.info(f"name: {self.name}, AWS credentials found.")
                self.session = boto3.Session(
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key
                )
                logger.info(f"name: {self.name}, Set boto session with acces ey and secret key is done")
            elif self.profile_name and not self.aws_access_key_id:
                logger.info(f"name: {self.name}, Try with profile name")
                # Check if the profile "qa" exists
                self.session = boto3.Session(profile_name=self.profile_name)
                logger.info(f"name: {self.name}, Using AWS profile: {self.profile_name}")
            else:
                raise Exception("No AWS credentials or profile found.")
        except Exception as e:
            logger.info(f"name: {self.name}, !!!!!!!!!!!!!!! error: {str(e)}")
            raise Exception(
                "Authentication failed. No AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY found in the environment, "
                "and the profile 'qa' does not exist."

            )

        # create clients for different services once we have auth
        assert self.session is not None, "AWS session for user is not initialized."
        self.iam = self.session.client('iam')

    def load_policies_from_files(self):
        """
        Loads IAM policies from JSON files in the specified folder.

        Parameters:
        folder_path (str): Path to the folder containing JSON policy files.

        Returns:
        dict: A dictionary where keys are policies names and values are the updated policies.
        """
        updated_policies = {}

        # Ensure the folder exists
        if not os.path.isdir(self.path_to_policies):
            logger.info(f"name: {self.name}, The specified folder does not exist: {self.path_to_policies}")
            return updated_policies

        # Iterate through JSON files in the folder
        for file_name in os.listdir(self.path_to_policies):
            if file_name.endswith(".json"):
                file_path = os.path.join(self.path_to_policies, file_name)

                # extract only file name
                policy_name = os.path.splitext(os.path.basename(file_path))[0]
                logger.info(f"name: {self.name}, policy_name: {policy_name}")

                # Load the policy JSON
                try:
                    with open(file_path, 'r') as policy_file:
                        policy = json.load(policy_file)
                        logger.info(f"name: {self.name}, Loaded policy from {file_name}")

                        # Save the updated policy
                        self.policies[policy_name] = policy

                except (json.JSONDecodeError, IOError) as e:
                    logger.info(f"name: {self.name}, Failed to load policy {file_name}: {str(e)}")

        return self.policies

    def get_policies(self):
        """
        Fetches all IAM policies.

        Returns:
        list: A list of policy names and their ARNs.
        """
        if not self.session:
            logger.info(f"name: {self.name}, Session is not initialized. Please validate credentials first.")
            return []

        try:
            paginator = self.iam.get_paginator('list_policies')
            policies = []
            for page in paginator.paginate(Scope='Local'):  # Local restricts to policies in the current account
                for policy in page.get('Policies', []):
                    policies.append({
                        "PolicyName": policy['PolicyName'],
                        "PolicyArn": policy['Arn']
                    })

            logger.info(f"name: {self.name}, Fetched {len(policies)} IAM policies")
            return policies
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to fetch IAM policies: {str(e)}")
            return []

    def remove_policy_by_name(self, policy_name):
        """
        Removes all IAM policies in the current AWS region.

        Returns:
        list: A list of policy ARNs that were successfully deleted.
        """
        if not self.session:
            logger.info(f"name: {self.name}, Session is not initialized. Please validate credentials first.")
            return []

        iam_client = self.session.client('iam')

        try:
            policies = self.get_policies()

            for policy in policies:
                policy_arn = policy['PolicyArn']
                current_policy_name = policy['PolicyName']
                if policy_name == current_policy_name:
                    try:
                        # Detach all policy versions before deletion
                        policy_versions = iam_client.list_policy_versions(PolicyArn=policy_arn)['Versions']
                        for version in policy_versions:
                            if not version['IsDefaultVersion']:
                                iam_client.delete_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=version['VersionId']
                                )

                        # Delete the policy
                        iam_client.delete_policy(PolicyArn=policy_arn)
                        logger.info(f"name: {self.name}, Deleted policy: {policy['PolicyName']} ({policy_arn})")
                    except Exception as e:
                        logger.info(f"name: {self.name}, Failed to delete policy {policy['PolicyName']} ({policy_arn}): {str(e)}")
            return

        except Exception as e:
            logger.info(f"name: {self.name}, Failed to remove policies: {str(e)}")
            return

    def remove_all_policies(self):
        """
        Removes all IAM policies in the current AWS region.

        Returns:
        list: A list of policy ARNs that were successfully deleted.
        """
        if not self.session:
            logger.info(f"name: {self.name}, Session is not initialized. Please validate credentials first.")
            return []

        iam_client = self.session.client('iam')
        deleted_policies = []

        try:
            policies = self.get_policies()

            for policy in policies:
                policy_arn = policy['PolicyArn']
                try:
                    # Detach all policy versions before deletion
                    policy_versions = iam_client.list_policy_versions(PolicyArn=policy_arn)['Versions']
                    for version in policy_versions:
                        if not version['IsDefaultVersion']:
                            iam_client.delete_policy_version(
                                PolicyArn=policy_arn,
                                VersionId=version['VersionId']
                            )

                    # Delete the policy
                    iam_client.delete_policy(PolicyArn=policy_arn)
                    deleted_policies.append(policy_arn)
                    logger.info(f"name: {self.name}, Deleted policy: {policy['PolicyName']} ({policy_arn})")
                except Exception as e:
                    logger.info(f"name: {self.name}, Failed to delete policy {policy['PolicyName']} ({policy_arn}): {str(e)}")

            return deleted_policies

        except Exception as e:
            logger.info(f"name: {self.name}, Failed to remove policies: {str(e)}")
            return deleted_policies

    def add_iam_policy(self, policy_name, policy_document):
        """
        Adds a new IAM policy to AWS.

        Parameters:
        policy_name (str): The name of the policy.
        policy_document (dict): The JSON document of the policy.

        Returns:
        str: The ARN of the created policy.
        """
        if not self.session:
            logger.info(f"name: {self.name}, Session is not initialized. Please validate credentials first.")
            return None

        iam_client = self.session.client('iam')

        try:
            response = iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
            policy_arn = response['Policy']['Arn']
            logger.info(f"name: {self.name}, Successfully created policy: {policy_name} (ARN: {policy_arn})")
            return policy_arn
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to create policy {policy_name}: {str(e)}")
            return None

    def create_iam_user(self, user_name, tags=None):
        """
        Creates a new IAM user.

        Parameters:
        user_name (str): The name of the new user.
        tags (list): Optional. A list of tags to associate with the user.

        Returns:
        dict: The details of the created user or an error message.
        """
        sleep(10.1)

        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return None

        try:
            # Create the user with optional tags
            params = {"UserName": user_name}
            if tags:
                params["Tags"] = tags

            response = self.iam.create_user(**params)
            user_details = response.get("User", {})
            logger.info(f"name: {self.name}, Successfully created IAM user: {user_name}")
            return user_details
        except self.iam.exceptions.EntityAlreadyExistsException:
            logger.info(f"name: {self.name}, IAM user {user_name} already exists.")
            return {"Error": "UserAlreadyExists", "UserName": user_name}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to create IAM user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def create_iam_user_credentials(self, user_name):
        """
        Creates AWS access credentials (Access Key ID and Secret Access Key) for an IAM user.

        Parameters:
        user_name (str): The name of the user for whom the credentials will be created.

        Returns:
        dict: A dictionary containing the Access Key ID and Secret Access Key or an error message.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return None

        try:
            # Create access key for the user
            response = self.iam.create_access_key(UserName=user_name)
            access_key = response.get("AccessKey", {})
            logger.info(f"name: {self.name}, Successfully created access credentials for user: {user_name}")

            # https://stackoverflow.com/questions/54214786/boto3-iam-user-creation-failing-with-invalidclienttokenid-the-security-token-i
            sleep(10)

            return {
                "AccessKeyId": access_key.get("AccessKeyId"),
                "SecretAccessKey": access_key.get("SecretAccessKey")
            }
        except self.iam.exceptions.LimitExceededException:
            logger.info(f"name: {self.name}, Cannot create access key for {user_name}: Limit exceeded.")
            return {"Error": "LimitExceeded", "UserName": user_name}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to create access credentials for {user_name}: {str(e)}")
            return {"Error": str(e)}

    def delete_iam_user_and_all_resources_by_user_name(self, user_name):
        """
        Deletes an IAM user and cleans up associated resources.

        Parameters:
        user_name (str): The name of the IAM user to delete.

        Returns:
        dict: A message indicating success or failure of the deletion.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            # Detach user from groups
            groups = self.iam.list_groups_for_user(UserName=user_name).get("Groups", [])
            for group in groups:
                self.iam.remove_user_from_group(
                    GroupName=group["GroupName"], UserName=user_name
                )
                logger.info(f"name: {self.name}, Removed user {user_name} from group {group['GroupName']}")

            # Delete inline policies
            policies = self.iam.list_user_policies(UserName=user_name).get("PolicyNames", [])
            for policy in policies:
                self.iam.delete_user_policy(UserName=user_name, PolicyName=policy)
                logger.info(f"name: {self.name}, Deleted inline policy {policy} from user {user_name}")

            # Detach managed policies
            attached_policies = self.iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
            for policy in attached_policies:
                self.iam.detach_user_policy(
                    UserName=user_name, PolicyArn=policy["PolicyArn"]
                )
                logger.info(f"name: {self.name}, Detached managed policy {policy['PolicyArn']} from user {user_name}")

            # Delete access keys
            access_keys = self.iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
            for key in access_keys:
                self.iam.delete_access_key(
                    UserName=user_name, AccessKeyId=key["AccessKeyId"]
                )
                logger.info(f"name: {self.name}, Deleted access key {key['AccessKeyId']} for user {user_name}")

            # Finally, delete the user
            self.iam.delete_user(UserName=user_name)
            logger.info(f"name: {self.name}, Successfully deleted IAM user: {user_name}")
            return {"Message": f"User {user_name} deleted successfully"}

        except self.iam.exceptions.NoSuchEntityException:
            logger.info(f"name: {self.name}, User {user_name} does not exist.")
            return {"Error": "UserDoesNotExist", "UserName": user_name}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to delete IAM user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def delete_iam_user_by_user_name(self, user_name):
        """
        Deletes an IAM user and cleans up associated resources.

        Parameters:
        user_name (str): The name of the IAM user to delete.

        Returns:
        dict: A message indicating success or failure of the deletion.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            # delete the user
            self.iam.delete_user(UserName=user_name)
            logger.info(f"name: {self.name}, Successfully deleted IAM user: {user_name}")
            return {"Message": f"User {user_name} deleted successfully"}

        except self.iam.exceptions.NoSuchEntityException:
            logger.info(f"name: {self.name}, User {user_name} does not exist.")
            return {"Error": "UserDoesNotExist", "UserName": user_name}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to delete IAM user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def list_users(self):
        """
        Lists all IAM users in the account.

        Returns:
        list: A list of IAM users or an error message.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            paginator = self.iam.get_paginator('list_users')
            users = []
            for page in paginator.paginate():
                users.extend(page.get('Users', []))
            logger.info(f"name: {self.name}, Fetched {len(users)} IAM users")
            return users
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to list users: {str(e)}")
            return {"Error": str(e)}

    def get_user(self, user_name=None):
        """
        Retrieves details of a specific IAM user.

        Parameters:
        user_name (str): Optional. The name of the user to retrieve details for. If None, retrieves the current user.

        Returns:
        dict: Details of the specified IAM user or an error message.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            response = self.iam.get_user(UserName=user_name) if user_name else self.iam.get_user()
            user = response.get("User", {})
            logger.info(f"name: {self.name}, Fetched details for user: {user.get('UserName', 'Unknown')}")
            return user
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to get user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def get_user_policy(self, user_name, policy_name):
        """
        Retrieves an inline policy document for a specific IAM user.

        Parameters:
        user_name (str): The name of the user.
        policy_name (str): The name of the policy.

        Returns:
        dict: The inline policy document or an error message.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            response = self.iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            policy_document = response.get("PolicyDocument", {})
            logger.info(f"name: {self.name}, Fetched policy {policy_name} for user {user_name}")
            return policy_document
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to get policy {policy_name} for user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def attach_user_policy(self, user_name, policy_arn):
        """
        Attaches a managed IAM policy to a user.

        Parameters:
        user_name (str): The name of the IAM user.
        policy_arn (str): The ARN of the managed policy to attach.

        Returns:
        dict: A message indicating success or failure of the attachment.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            # Attach the policy to the user
            self.iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            logger.info(f"name: {self.name}, Successfully attached policy {policy_arn} to user {user_name}")
            return {"Message": f"Policy {policy_arn} attached to user {user_name}"}
        except self.iam.exceptions.NoSuchEntityException:
            logger.info(f"name: {self.name}, User {user_name} does not exist.")
            return {"Error": "UserNotFound", "UserName": user_name}
        except self.iam.exceptions.NoSuchEntityException:
            logger.info(f"name: {self.name}, Policy {policy_arn} does not exist.")
            return {"Error": "PolicyNotFound", "PolicyArn": policy_arn}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to attach policy {policy_arn} to user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def create_group(self, group_name):
        """
        Creates an IAM group.

        Parameters:
        group_name (str): The name of the group to create.

        Returns:
        dict: A message indicating success or failure of the group creation.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            response = self.iam.create_group(GroupName=group_name)
            group = response.get("Group", {})
            logger.info(f"name: {self.name}, Successfully created group: {group.get('GroupName')}")
            return {
                "Message": f"Group {group_name} created successfully.",
                "GroupArn": group.get("Arn"),
            }
        except self.iam.exceptions.EntityAlreadyExistsException:
            logger.info(f"name: {self.name}, Group {group_name} already exists.")
            return {"Error": "GroupAlreadyExists", "GroupName": group_name}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to create group {group_name}: {str(e)}")
            return {"Error": str(e)}

    def delete_group(self, group_name):
        """
        Deletes an IAM group.

        Parameters:
        group_name (str): The name of the group to delete.

        Returns:
        dict: A message indicating success or failure of the group deletion.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            # Attempt to delete the group
            self.iam.delete_group(GroupName=group_name)
            logger.info(f"name: {self.name}, Successfully deleted group: {group_name}")
            return {"Message": f"Group {group_name} deleted successfully."}
        except self.iam.exceptions.NoSuchEntityException:
            logger.info(f"name: {self.name}, Group {group_name} does not exist.")
            return {"Error": "GroupNotFound", "GroupName": group_name}
        except self.iam.exceptions.DeleteConflictException as e:
            logger.info(f"name: {self.name}, Cannot delete group {group_name} because it is not empty: {str(e)}")
            return {"Error": "DeleteConflict", "GroupName": group_name, "Details": str(e)}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to delete group {group_name}: {str(e)}")
            return {"Error": str(e)}

    def add_user_to_group(self, user_name, group_name):
        """
        Adds an IAM user to a group.

        Parameters:
        user_name (str): The name of the user.
        group_name (str): The name of the group.

        Returns:
        dict: A message indicating success or failure of the operation.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            self.iam.add_user_to_group(GroupName=group_name, UserName=user_name)
            logger.info(f"name: {self.name}, Successfully added user {user_name} to group {group_name}")
            return {"Message": f"User {user_name} added to group {group_name}"}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to add user {user_name} to group {group_name}: {str(e)}")
            return {"Error": str(e)}

    def remove_user_from_group(self, user_name, group_name):
        """
        Removes an IAM user from a group.

        Parameters:
        user_name (str): The name of the user.
        group_name (str): The name of the group.

        Returns:
        dict: A message indicating success or failure of the operation.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            self.iam.remove_user_from_group(GroupName=group_name, UserName=user_name)
            logger.info(f"name: {self.name}, Successfully removed user {user_name} from group {group_name}")
            return {"Message": f"User {user_name} removed from group {group_name}"}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to remove user {user_name} from group {group_name}: {str(e)}")
            return {"Error": str(e)}

    def list_inline_user_policies(self, user_name):
        """
        Lists all inline policies attached to a specific IAM user.

        Parameters:
        user_name (str): The name of the user.

        Returns:
        list: A list of inline policy names or an error message.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            response = self.iam.list_user_policies(UserName=user_name)
            policies = response.get("PolicyNames", [])
            logger.info(f"name: {self.name}, Fetched {len(policies)} inline policies for user {user_name}")
            return policies
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to list inline policies for user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def list_attached_user_policies(self, user_name):
        """
        Lists all managed policies attached to a specific IAM user.

        Parameters:
        user_name (str): The name of the user.

        Returns:
        list: A list of attached managed policy ARNs or an error message.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            response = self.iam.list_attached_user_policies(UserName=user_name)
            policies = response.get("AttachedPolicies", [])
            logger.info(f"name: {self.name}, Fetched {len(policies)} managed policies for user {user_name}")
            return policies
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to list attached managed policies for user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def list_groups_for_user(self, user_name):
        """
        Lists all groups a specific IAM user belongs to.

        Parameters:
        user_name (str): The name of the user.

        Returns:
        list: A list of groups the user belongs to or an error message.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            response = self.iam.list_groups_for_user(UserName=user_name)
            groups = response.get("Groups", [])
            logger.info(f"name: {self.name}, Fetched {len(groups)} groups for user {user_name}")
            return groups
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to list groups for user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def update_user(self, old_user_name, new_user_name):
        """
        Updates an IAM user's name.

        Parameters:
        old_user_name (str): The current name of the IAM user.
        new_user_name (str): The new name to assign to the IAM user.

        Returns:
        dict: A message indicating success or failure of the update.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            self.iam.update_user(UserName=old_user_name, NewUserName=new_user_name)
            logger.info(f"name: {self.name}, Successfully updated user {old_user_name} to {new_user_name}")
            return {"Message": f"User {old_user_name} updated to {new_user_name}"}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to update user {old_user_name}: {str(e)}")
            return {"Error": str(e)}

    def detach_user_policy(self, user_name, policy_arn):
        """
        Detaches a managed policy from an IAM user.

        Parameters:
        user_name (str): The name of the user.
        policy_arn (str): The ARN of the managed policy to detach.

        Returns:
        dict: A message indicating success or failure of the detachment.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            self.iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            logger.info(f"name: {self.name}, Successfully detached policy {policy_arn} from user {user_name}")
            return {"Message": f"Policy {policy_arn} detached from user {user_name}"}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to detach policy {policy_arn} from user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def put_user_inline_policy(self, user_name, policy_name, policy_document):
        """
        Adds or updates an inline policy for an IAM user.

        Parameters:
        user_name (str): The name of the user.
        policy_name (str): The name of the policy.
        policy_document (dict): The policy document to attach.

        Returns:
        dict: A message indicating success or failure of the operation.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            self.iam.put_user_policy(
                UserName=user_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
            logger.info(f"name: {self.name}, Successfully added/updated inline policy {policy_name} for user {user_name}")
            return {"Message": f"Inline policy {policy_name} added/updated for user {user_name}"}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to add/update policy {policy_name} for user {user_name}: {str(e)}")
            return {"Error": str(e)}

    def delete_user_policy(self, user_name, policy_name):
        """
        Deletes an inline policy attached to an IAM user.

        Parameters:
        user_name (str): The name of the user.
        policy_name (str): The name of the policy to delete.

        Returns:
        dict: A message indicating success or failure of the deletion.
        """
        if not self.iam:
            logger.info(f"name: {self.name}, IAM client is not initialized. Please validate credentials first.")
            return {"Error": "IAMClientNotInitialized"}

        try:
            self.iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
            logger.info(f"name: {self.name}, Successfully deleted inline policy {policy_name} for user {user_name}")
            return {"Message": f"Inline policy {policy_name} deleted for user {user_name}"}
        except Exception as e:
            logger.info(f"name: {self.name}, Failed to delete inline policy {policy_name} for user {user_name}: {str(e)}")
            return {"Error": str(e)}



# Example Usage
if __name__ == "__main__":
    aws_handler = AWSHandler()
    try:
        aws_handler.validate_credentials()
        logger.info(f"name: {self.name}, Authentication successful!")
    except NoCredentialsError as e:
        logger.info(f"name: {self.name}, AWS credentials error {str(e)}")


