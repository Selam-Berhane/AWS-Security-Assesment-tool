"""
IAM Security Analyzer

Handles IAM users, policies, and access key analysis
"""

import datetime
import logging
from typing import Any, Dict, List, Optional

import boto3

from .credential_manager import CredentialReportManager

logger = logging.getLogger(__name__)


class IAMAnalyzer:
    """Handles IAM security analysis"""

    def __init__(self, session: boto3.Session, credential_manager: CredentialReportManager):
        self.session = session
        self.credential_manager = credential_manager

    def analyze_iam_security(self) -> Dict[str, Any]:
        """Comprehensive IAM security analysis"""
        logger.info("Analyzing IAM security posture...")
        iam = self.session.client('iam')

        findings = {
            'users_with_console_access': [],
            'users_without_mfa': [],
            'overprivileged_policies': [],
            'unused_access_keys': [],
            'root_account_issues': [],
            'policy_analysis': []
        }

        try:
            # Analyze IAM users
            self._analyze_users(iam, findings)

            # Analyze policies
            self._analyze_policies(iam, findings)

            # Check root account
            findings['root_account_issues'] = self._analyze_root_account()

        except Exception as e:
            logger.error(f"IAM analysis failed: {e}")

        return findings

    def _analyze_users(self, iam, findings: Dict[str, Any]) -> None:
        """Analyze IAM users for security issues"""
        try:
            users = iam.list_users()['Users']
            logger.info(f"Analyzing {len(users)} IAM users")

            for user in users:
                username = user['UserName']

                # Check console access and MFA
                try:
                    iam.get_login_profile(UserName=username)
                    findings['users_with_console_access'].append(username)

                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        findings['users_without_mfa'].append(username)

                except iam.exceptions.NoSuchEntityException:
                    # User doesn't have console access
                    pass

                # Analyze access keys
                self._analyze_user_access_keys(iam, username, findings)

        except Exception as e:
            logger.error(f"User analysis failed: {e}")

    def _analyze_user_access_keys(self, iam, username: str, findings: Dict[str, Any]) -> None:
        """Analyze access keys for a user"""
        try:
            access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']

            for key in access_keys:
                key_id = key['AccessKeyId']
                last_used = self._get_access_key_last_used(iam, key_id)

                if self._is_key_unused(last_used):
                    findings['unused_access_keys'].append({
                        'user': username,
                        'key_id': key_id,
                        'last_used': last_used
                    })

        except Exception as e:
            logger.error(f"Access key analysis failed for user {username}: {e}")

    def _analyze_policies(self, iam, findings: Dict[str, Any]) -> None:
        """Analyze IAM policies for overprivileged access"""
        try:
            policies = iam.list_policies(Scope='Local')['Policies']
            logger.info(f"Analyzing {len(policies)} customer-managed policies")

            for policy in policies:
                policy_doc = self._get_policy_document(iam, policy['Arn'])
                if policy_doc:
                    risk_score = self._analyze_policy_risk(policy_doc)
                    if risk_score > 7:
                        findings['overprivileged_policies'].append({
                            'policy_name': policy['PolicyName'],
                            'arn': policy['Arn'],
                            'risk_score': risk_score
                        })

        except Exception as e:
            logger.error(f"Policy analysis failed: {e}")

    def _analyze_root_account(self) -> List[Dict]:
        """Analyze root account security"""
        # Basic root account analysis
        return [{
            'check': 'root_mfa',
            'status': 'unknown',
            'recommendation': 'Enable MFA on root account'
        }]

    def _get_access_key_last_used(self, iam, access_key_id: str) -> Optional[datetime.datetime]:
        """Get last used date for access key"""
        try:
            response = iam.get_access_key_last_used(AccessKeyId=access_key_id)
            return response.get('AccessKeyLastUsed', {}).get('LastUsedDate')
        except Exception as e:
            logger.error(f"Failed to get access key usage for {access_key_id}: {e}")
            return None

    def _is_key_unused(self, last_used: Optional[datetime.datetime], days_threshold: int = 90) -> bool:
        """Check if access key is unused"""
        if not last_used:
            return True
        days_since_used = (datetime.datetime.now(datetime.timezone.utc) - last_used).days
        return days_since_used > days_threshold

    def _get_policy_document(self, iam, policy_arn: str) -> Optional[Dict]:
        """Get IAM policy document"""
        try:
            policy = iam.get_policy(PolicyArn=policy_arn)
            version_id = policy['Policy']['DefaultVersionId']
            policy_version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            return policy_version['PolicyVersion']['Document']
        except Exception as e:
            logger.error(f"Failed to get policy document for {policy_arn}: {e}")
            return None

    def _analyze_policy_risk(self, policy_doc: Dict) -> int:
        """Analyze IAM policy for risk factors (0-10 scale)"""
        risk_score = 0
        statements = policy_doc.get('Statement', [])

        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])

                if not isinstance(actions, list):
                    actions = [actions]
                if not isinstance(resources, list):
                    resources = [resources]

                # Risk scoring logic
                if '*' in actions:
                    risk_score += 4
                elif any('*' in action for action in actions):
                    risk_score += 2

                if '*' in resources:
                    risk_score += 3

                dangerous_actions = ['iam:*', 'ec2:*', 's3:*', 'sts:AssumeRole']
                if any(action in dangerous_actions for action in actions):
                    risk_score += 2

        return min(risk_score, 10)