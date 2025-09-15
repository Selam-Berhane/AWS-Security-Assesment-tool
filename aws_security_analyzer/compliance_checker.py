"""
Compliance Standards Checker

Handles compliance checking against CIS benchmarks and AWS best practices
"""

import datetime
import logging
from typing import Any, Dict

import boto3

from .credential_manager import CredentialReportManager

logger = logging.getLogger(__name__)


class ComplianceChecker:
    """Handles compliance standards checking"""

    def __init__(self, session: boto3.Session, credential_manager: CredentialReportManager):
        self.session = session
        self.credential_manager = credential_manager

    def check_compliance_standards(self) -> Dict[str, Any]:
        """Check compliance against CIS benchmarks and AWS best practices"""
        logger.info("Checking compliance standards...")

        compliance_results = {
            'cis_benchmarks': {},
            'aws_foundational_standards': {},
            'compliance_score': 0
        }

        # CIS Benchmark checks
        cis_checks = {
            'root_mfa_enabled': self._check_root_mfa(),
            'password_policy_compliant': self._check_password_policy(),
            'unused_credentials_removed': self._check_unused_credentials(),
            'access_keys_rotated': self._check_access_key_rotation(),
            'cloudtrail_enabled_all_regions': self._check_cloudtrail_global(),
            's3_bucket_public_access_blocked': self._check_s3_public_access()
        }

        compliance_results['cis_benchmarks'] = cis_checks

        # Calculate compliance score
        total_checks = len(cis_checks)
        passed_checks = sum(1 for result in cis_checks.values() if result.get('compliant', False))
        compliance_results['compliance_score'] = (passed_checks / total_checks) * 100

        logger.info(f"Compliance score: {compliance_results['compliance_score']:.1f}% ({passed_checks}/{total_checks} checks passed)")

        return compliance_results

    def _check_root_mfa(self) -> Dict[str, Any]:
        """Check if root account has MFA enabled"""
        credential_report = self.credential_manager.get_credential_report()

        if not credential_report:
            return {
                'compliant': False,
                'description': 'Unable to retrieve credential report',
                'remediation': 'Enable MFA on root account and verify credential report access',
                'severity': 'HIGH'
            }

        for row in credential_report:
            if row['user'] == '<root_account>':
                mfa_active = row['mfa_active'] == 'true'
                return {
                    'compliant': mfa_active,
                    'description': f'Root account MFA is {"enabled" if mfa_active else "disabled"}',
                    'remediation': 'Enable MFA on root account' if not mfa_active else 'Root MFA is properly configured',
                    'severity': 'HIGH' if not mfa_active else 'INFO'
                }

        return {
            'compliant': False,
            'description': 'Unable to find root account in credential report',
            'remediation': 'Verify root account MFA configuration manually',
            'severity': 'MEDIUM'
        }

    def _check_password_policy(self) -> Dict[str, Any]:
        """Check password policy compliance"""
        try:
            iam = self.session.client('iam')
            policy = iam.get_account_password_policy()['PasswordPolicy']

            # CIS requirements
            compliant = (
                policy.get('MinimumPasswordLength', 0) >= 14 and
                policy.get('RequireUppercaseCharacters', False) and
                policy.get('RequireLowercaseCharacters', False) and
                policy.get('RequireNumbers', False) and
                policy.get('RequireSymbols', False)
            )

            return {
                'compliant': compliant,
                'description': f'Password policy {"meets" if compliant else "does not meet"} CIS requirements',
                'remediation': 'Configure password policy according to CIS benchmarks',
                'severity': 'MEDIUM'
            }

        except Exception as e:
            logger.error(f"Password policy check failed: {e}")
            return {
                'compliant': False,
                'description': 'No password policy configured',
                'remediation': 'Configure account password policy',
                'severity': 'MEDIUM'
            }

    def _check_unused_credentials(self) -> Dict[str, Any]:
        """Check for unused credentials"""
        credential_report = self.credential_manager.get_credential_report()

        if not credential_report:
            return {
                'compliant': False,
                'description': 'Unable to retrieve credential report for credential analysis',
                'remediation': 'Review and remove unused credentials manually',
                'severity': 'MEDIUM'
            }

        unused_count = 0
        threshold_days = 90

        for row in credential_report:
            if row['user'] == '<root_account>':
                continue

            # Check password usage
            password_last_used = row.get('password_last_used', 'N/A')
            if password_last_used not in ['N/A', 'no_information'] and password_last_used:
                try:
                    last_used_date = datetime.datetime.fromisoformat(password_last_used.replace('Z', '+00:00'))
                    days_since_used = (datetime.datetime.now(datetime.timezone.utc) - last_used_date).days
                    if days_since_used > threshold_days:
                        unused_count += 1
                except (ValueError, AttributeError):
                    pass

            # Check access keys
            for key_num in ['1', '2']:
                key_active = row.get(f'access_key_{key_num}_active', 'false') == 'true'
                key_last_used = row.get(f'access_key_{key_num}_last_used_date', 'N/A')

                if key_active and key_last_used not in ['N/A', 'no_information'] and key_last_used:
                    try:
                        last_used_date = datetime.datetime.fromisoformat(key_last_used.replace('Z', '+00:00'))
                        days_since_used = (datetime.datetime.now(datetime.timezone.utc) - last_used_date).days
                        if days_since_used > threshold_days:
                            unused_count += 1
                    except (ValueError, AttributeError):
                        pass

        return {
            'compliant': unused_count == 0,
            'description': f'Found {unused_count} potentially unused credentials',
            'remediation': 'Review and remove unused credentials',
            'severity': 'HIGH' if unused_count > 5 else 'MEDIUM' if unused_count > 0 else 'INFO'
        }

    def _check_access_key_rotation(self) -> Dict[str, Any]:
        """Check access key rotation"""
        # Placeholder for access key rotation check
        return {
            'compliant': False,
            'description': 'Access key rotation compliance check',
            'remediation': 'Rotate access keys regularly (90 days)',
            'severity': 'MEDIUM'
        }

    def _check_cloudtrail_global(self) -> Dict[str, Any]:
        """Check CloudTrail global configuration"""
        # Placeholder for CloudTrail global check
        return {
            'compliant': False,
            'description': 'CloudTrail global logging verification',
            'remediation': 'Enable multi-region CloudTrail',
            'severity': 'HIGH'
        }

    def _check_s3_public_access(self) -> Dict[str, Any]:
        """Check S3 public access configuration"""
        # Placeholder for S3 public access check
        return {
            'compliant': False,
            'description': 'S3 public access block verification',
            'remediation': 'Enable S3 account-level public access block',
            'severity': 'HIGH'
        }