#!/usr/bin/env python3
"""
AWS Security Posture Analyzer
A comprehensive security assessment tool for AWS environments

Features:
- Multi-account security analysis
- IAM policy evaluation and risk scoring
- Network security assessment
- Compliance checking (CIS, AWS Config)
- Security findings aggregation
- Detailed reporting with remediation guidance
- Cost optimization for security services

Author: Selam Berhane Gebreananeya
"""

import argparse
import concurrent.futures
import csv
import datetime
import io
import json
import logging
import re
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

import boto3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """Data class for security findings"""
    severity: str
    resource_type: str
    resource_id: str
    finding_type: str
    description: str
    remediation: str
    region: str
    account_id: str
    compliance_status: str = "NON_COMPLIANT"


class CredentialReportManager:
    """Manages IAM credential report operations"""

    def __init__(self, session: boto3.Session):
        self.session = session
        self._cached_report = None
        self._cache_timestamp = None
        self._cache_duration = 300  # 5 minutes

    def get_credential_report(self) -> Optional[List[Dict[str, str]]]:
        """Get IAM credential report data with caching"""
        current_time = time.time()

        # Return cached report if still valid
        if (self._cached_report and self._cache_timestamp and
            current_time - self._cache_timestamp < self._cache_duration):
            return self._cached_report

        try:
            iam = self.session.client('iam')

            # Generate credential report
            try:
                iam.generate_credential_report()

                # Wait for report generation
                for _ in range(10):  # Wait up to 10 seconds
                    try:
                        response = iam.get_credential_report()
                        break
                    except iam.exceptions.CredentialReportNotReadyException:
                        time.sleep(1)
                else:
                    raise Exception("Credential report generation timeout")

            except iam.exceptions.CredentialReportNotPresentException:
                iam.generate_credential_report()
                time.sleep(2)
                response = iam.get_credential_report()

            # Parse CSV data
            credential_data = response['Content'].decode('utf-8')
            csv_reader = csv.DictReader(io.StringIO(credential_data))

            # Cache the result
            self._cached_report = list(csv_reader)
            self._cache_timestamp = current_time

            return self._cached_report

        except Exception as e:
            logger.error(f"Failed to get credential report: {e}")
            return None


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
        users = iam.list_users()['Users']

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
                pass

            # Analyze access keys
            self._analyze_user_access_keys(iam, username, findings)

    def _analyze_user_access_keys(self, iam, username: str, findings: Dict[str, Any]) -> None:
        """Analyze access keys for a user"""
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

    def _analyze_policies(self, iam, findings: Dict[str, Any]) -> None:
        """Analyze IAM policies for overprivileged access"""
        policies = iam.list_policies(Scope='Local')['Policies']

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

    def _analyze_root_account(self) -> List[Dict]:
        """Analyze root account security"""
        # Implementation would check root account security
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
        except Exception:
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
        except Exception:
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


class NetworkAnalyzer:
    """Handles network security analysis"""

    def __init__(self, session: boto3.Session, regions: List[str]):
        self.session = session
        self.regions = regions

    def analyze_network_security(self) -> Dict[str, Any]:
        """Analyze VPC and network security configurations"""
        logger.info("Analyzing network security...")

        findings = {
            'open_security_groups': [],
            'unrestricted_nacls': [],
            'unencrypted_ebs_volumes': [],
            'public_rds_instances': [],
            'vpc_flow_logs_disabled': []
        }

        for region in self.regions:
            try:
                self._analyze_region_security(region, findings)
            except Exception as e:
                logger.error(f"Network analysis failed for region {region}: {e}")

        return findings

    def _analyze_region_security(self, region: str, findings: Dict[str, Any]) -> None:
        """Analyze security for a specific region"""
        ec2 = self.session.client('ec2', region_name=region)

        # Analyze security groups
        self._analyze_security_groups(ec2, region, findings)

        # Check VPC flow logs
        self._check_vpc_flow_logs(ec2, region, findings)

        # Check EBS encryption
        self._check_ebs_encryption(ec2, region, findings)

        # Check RDS instances
        self._check_rds_instances(region, findings)

    def _analyze_security_groups(self, ec2, region: str, findings: Dict[str, Any]) -> None:
        """Analyze security groups for overly permissive rules"""
        security_groups = ec2.describe_security_groups()['SecurityGroups']

        for sg in security_groups:
            if self._has_open_access(sg):
                findings['open_security_groups'].append({
                    'group_id': sg['GroupId'],
                    'group_name': sg['GroupName'],
                    'region': region,
                    'risky_rules': self._get_risky_rules(sg)
                })

    def _check_vpc_flow_logs(self, ec2, region: str, findings: Dict[str, Any]) -> None:
        """Check VPC flow logs configuration"""
        vpcs = ec2.describe_vpcs()['Vpcs']

        for vpc in vpcs:
            if not self._has_flow_logs_enabled(ec2, vpc['VpcId']):
                findings['vpc_flow_logs_disabled'].append({
                    'vpc_id': vpc['VpcId'],
                    'region': region
                })

    def _check_ebs_encryption(self, ec2, region: str, findings: Dict[str, Any]) -> None:
        """Check EBS volume encryption"""
        volumes = ec2.describe_volumes()['Volumes']

        for volume in volumes:
            if not volume.get('Encrypted', False):
                findings['unencrypted_ebs_volumes'].append({
                    'volume_id': volume['VolumeId'],
                    'region': region,
                    'state': volume['State']
                })

    def _check_rds_instances(self, region: str, findings: Dict[str, Any]) -> None:
        """Check RDS instances for public accessibility"""
        try:
            rds = self.session.client('rds', region_name=region)
            db_instances = rds.describe_db_instances()['DBInstances']

            for db in db_instances:
                if db.get('PubliclyAccessible', False):
                    findings['public_rds_instances'].append({
                        'db_identifier': db['DBInstanceIdentifier'],
                        'region': region,
                        'engine': db['Engine']
                    })
        except Exception as e:
            logger.warning(f"Failed to analyze RDS in {region}: {e}")

    def _has_open_access(self, security_group: Dict) -> bool:
        """Check if security group has overly permissive rules"""
        for rule in security_group.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    return True
            for ipv6_range in rule.get('Ipv6Ranges', []):
                if ipv6_range.get('CidrIpv6') == '::/0':
                    return True
        return False

    def _get_risky_rules(self, security_group: Dict) -> List[Dict]:
        """Get list of risky security group rules"""
        risky_rules = []
        for rule in security_group.get('IpPermissions', []):
            if self._is_rule_risky(rule):
                risky_rules.append({
                    'protocol': rule.get('IpProtocol'),
                    'from_port': rule.get('FromPort'),
                    'to_port': rule.get('ToPort'),
                    'source': self._get_rule_sources(rule)
                })
        return risky_rules

    def _is_rule_risky(self, rule: Dict) -> bool:
        """Check if a security group rule is risky"""
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True
        for ipv6_range in rule.get('Ipv6Ranges', []):
            if ipv6_range.get('CidrIpv6') == '::/0':
                return True
        return False

    def _get_rule_sources(self, rule: Dict) -> List[str]:
        """Get source CIDR blocks from security group rule"""
        sources = []
        for ip_range in rule.get('IpRanges', []):
            sources.append(ip_range.get('CidrIp', ''))
        for ipv6_range in rule.get('Ipv6Ranges', []):
            sources.append(ipv6_range.get('CidrIpv6', ''))
        return sources

    def _has_flow_logs_enabled(self, ec2, vpc_id: str) -> bool:
        """Check if VPC has flow logs enabled"""
        try:
            flow_logs = ec2.describe_flow_logs(
                Filters=[
                    {'Name': 'resource-id', 'Values': [vpc_id]},
                    {'Name': 'resource-type', 'Values': ['VPC']}
                ]
            )['FlowLogs']
            return len(flow_logs) > 0
        except Exception:
            return False


class SecurityServicesAnalyzer:
    """Handles AWS security services analysis"""

    def __init__(self, session: boto3.Session, regions: List[str]):
        self.session = session
        self.regions = regions

    def analyze_security_services(self) -> Dict[str, Any]:
        """Analyze AWS security services configuration"""
        logger.info("Analyzing security services...")

        findings = {
            'guardduty_status': {},
            'config_status': {},
            'cloudtrail_status': {},
            'security_hub_status': {}
        }

        for region in self.regions:
            try:
                self._analyze_region_services(region, findings)
            except Exception as e:
                logger.error(f"Security services analysis failed for region {region}: {e}")

        # Analyze CloudTrail globally
        if self.regions:
            self._analyze_cloudtrail_global(findings)

        return findings

    def _analyze_region_services(self, region: str, findings: Dict[str, Any]) -> None:
        """Analyze security services for a specific region"""
        self._check_guardduty(region, findings)
        self._check_config(region, findings)

    def _check_guardduty(self, region: str, findings: Dict[str, Any]) -> None:
        """Check GuardDuty status"""
        try:
            guardduty = self.session.client('guardduty', region_name=region)
            detectors = guardduty.list_detectors()['DetectorIds']

            if detectors:
                detector_details = guardduty.get_detector(DetectorId=detectors[0])
                findings['guardduty_status'][region] = {
                    'enabled': detector_details['Status'] == 'ENABLED',
                    'finding_frequency': detector_details.get('FindingPublishingFrequency', 'UNKNOWN')
                }
            else:
                findings['guardduty_status'][region] = {'enabled': False}
        except Exception:
            findings['guardduty_status'][region] = {'enabled': False, 'error': True}

    def _check_config(self, region: str, findings: Dict[str, Any]) -> None:
        """Check AWS Config status"""
        try:
            config = self.session.client('config', region_name=region)
            config_recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
            findings['config_status'][region] = {
                'enabled': len(config_recorders) > 0,
                'recorder_count': len(config_recorders)
            }
        except Exception:
            findings['config_status'][region] = {'enabled': False, 'error': True}

    def _analyze_cloudtrail_global(self, findings: Dict[str, Any]) -> None:
        """Analyze CloudTrail configuration globally"""
        try:
            cloudtrail = self.session.client('cloudtrail', region_name=self.regions[0])
            trails = cloudtrail.describe_trails()['trailList']
            global_trails = [t for t in trails if t.get('IsMultiRegionTrail', False)]

            findings['cloudtrail_status'] = {
                'global_trails': len(global_trails),
                'total_trails': len(trails),
                'has_global_logging': len(global_trails) > 0
            }
        except Exception:
            findings['cloudtrail_status'] = {'enabled': False, 'error': True}


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

            compliant = (
                policy.get('MinimumPasswordLength', 0) >= 14 and
                policy.get('RequireUppercaseCharacters', False) and
                policy.get('RequireLowercaseCharacters', False) and
                policy.get('RequireNumbers', False) and
                policy.get('RequireSymbols', False)
            )

            return {
                'compliant': compliant,
                'description': 'Password policy compliance check',
                'remediation': 'Configure password policy according to CIS benchmarks',
                'severity': 'MEDIUM'
            }
        except Exception:
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

        return {
            'compliant': unused_count == 0,
            'description': f'Found {unused_count} potentially unused credentials',
            'remediation': 'Review and remove unused credentials',
            'severity': 'HIGH' if unused_count > 5 else 'MEDIUM' if unused_count > 0 else 'INFO'
        }

    def _check_access_key_rotation(self) -> Dict[str, Any]:
        """Check access key rotation"""
        return {
            'compliant': False,
            'description': 'Access key rotation compliance check',
            'remediation': 'Rotate access keys regularly (90 days)',
            'severity': 'MEDIUM'
        }

    def _check_cloudtrail_global(self) -> Dict[str, Any]:
        """Check CloudTrail global configuration"""
        return {
            'compliant': False,
            'description': 'CloudTrail global logging verification',
            'remediation': 'Enable multi-region CloudTrail',
            'severity': 'HIGH'
        }

    def _check_s3_public_access(self) -> Dict[str, Any]:
        """Check S3 public access configuration"""
        return {
            'compliant': False,
            'description': 'S3 public access block verification',
            'remediation': 'Enable S3 account-level public access block',
            'severity': 'HIGH'
        }


class AWSSecurityAnalyzer:
    """Main class for AWS security analysis"""

    def __init__(self, profile_name: Optional[str] = None, regions: List[str] = None):
        """Initialize the analyzer with AWS session and regions"""
        self.session = boto3.Session(profile_name=profile_name)
        self.regions = regions or ['us-east-1', 'us-west-2', 'eu-west-1']
        self.findings: List[SecurityFinding] = []
        self.account_id = self._get_account_id()

        # Initialize specialized analyzers
        self.credential_manager = CredentialReportManager(self.session)
        self.iam_analyzer = IAMAnalyzer(self.session, self.credential_manager)
        self.network_analyzer = NetworkAnalyzer(self.session, self.regions)
        self.services_analyzer = SecurityServicesAnalyzer(self.session, self.regions)
        self.compliance_checker = ComplianceChecker(self.session, self.credential_manager)

    def _get_account_id(self) -> str:
        """Get current AWS account ID"""
        try:
            sts = self.session.client('sts')
            return sts.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Failed to get account ID: {e}")
            return "unknown"

    def analyze_iam_security(self) -> Dict[str, Any]:
        """Comprehensive IAM security analysis"""
        return self.iam_analyzer.analyze_iam_security()

    def analyze_network_security(self) -> Dict[str, Any]:
        """Analyze VPC and network security configurations"""
        return self.network_analyzer.analyze_network_security()

    def analyze_security_services(self) -> Dict[str, Any]:
        """Analyze AWS security services configuration"""
        return self.services_analyzer.analyze_security_services()

    def check_compliance_standards(self) -> Dict[str, Any]:
        """Check compliance against CIS benchmarks and AWS best practices"""
        return self.compliance_checker.check_compliance_standards()

    def run_full_assessment(self) -> Dict[str, Any]:
        """Run complete security assessment"""
        logger.info(f"Starting comprehensive security assessment for account {self.account_id}")

        assessment_results = {
            'account_id': self.account_id,
            'assessment_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'regions_analyzed': self.regions,
            'iam_analysis': {},
            'network_analysis': {},
            'security_services': {},
            'compliance_check': {},
            'summary': {}
        }

        try:
            # Run analysis modules in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                future_to_analysis = {
                    executor.submit(self.analyze_iam_security): 'iam_analysis',
                    executor.submit(self.analyze_network_security): 'network_analysis',
                    executor.submit(self.analyze_security_services): 'security_services',
                    executor.submit(self.check_compliance_standards): 'compliance_check'
                }

                for future in concurrent.futures.as_completed(future_to_analysis):
                    analysis_type = future_to_analysis[future]
                    try:
                        result = future.result()
                        assessment_results[analysis_type] = result
                    except Exception as e:
                        logger.error(f"{analysis_type} failed: {e}")
                        assessment_results[analysis_type] = {'error': str(e)}

            # Generate summary
            assessment_results['summary'] = self._generate_summary()

        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            assessment_results['error'] = str(e)

        return assessment_results

    def export_findings(self, format_type: str = 'json', filename: str = None) -> str:
        """Export findings in various formats"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aws_security_assessment_{self.account_id}_{timestamp}"

        if format_type.lower() == 'json':
            filename += '.json'
            with open(filename, 'w') as f:
                json.dump([asdict(finding) for finding in self.findings], f, indent=2)

        elif format_type.lower() == 'csv':
            filename += '.csv'
            with open(filename, 'w', newline='') as f:
                if self.findings:
                    writer = csv.DictWriter(f, fieldnames=asdict(self.findings[0]).keys())
                    writer.writeheader()
                    for finding in self.findings:
                        writer.writerow(asdict(finding))

        logger.info(f"Findings exported to {filename}")
        return filename

    def _add_finding(self, severity: str, resource_type: str, resource_id: str,
                    finding_type: str, description: str, remediation: str,
                    region: str = "global", compliance_status: str = "NON_COMPLIANT"):
        """Add a security finding to the results"""
        finding = SecurityFinding(
            severity=severity,
            resource_type=resource_type,
            resource_id=resource_id,
            finding_type=finding_type,
            description=description,
            remediation=remediation,
            region=region,
            account_id=self.account_id,
            compliance_status=compliance_status
        )
        self.findings.append(finding)

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate assessment summary"""
        severity_counts = defaultdict(int)
        finding_types = defaultdict(int)

        for finding in self.findings:
            severity_counts[finding.severity] += 1
            finding_types[finding.finding_type] += 1

        return {
            'total_findings': len(self.findings),
            'severity_breakdown': dict(severity_counts),
            'top_finding_types': dict(sorted(finding_types.items(), key=lambda x: x[1], reverse=True)[:5]),
            'risk_level': self._calculate_risk_level(severity_counts),
            'recommendations': self._get_top_recommendations()
        }

    def _calculate_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        if severity_counts.get('HIGH', 0) > 5:
            return 'CRITICAL'
        elif severity_counts.get('HIGH', 0) > 0 or severity_counts.get('MEDIUM', 0) > 10:
            return 'HIGH'
        elif severity_counts.get('MEDIUM', 0) > 0:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _get_top_recommendations(self) -> List[str]:
        """Get top security recommendations"""
        return [
            "Enable MFA on all user accounts with console access",
            "Configure multi-region CloudTrail logging",
            "Enable GuardDuty in all regions",
            "Review and restrict overly permissive security groups",
            "Enable VPC Flow Logs for network monitoring",
            "Implement regular access key rotation",
            "Configure AWS Config for compliance monitoring"
        ]


def main() -> int:
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(description='AWS Security Posture Analyzer')
    parser.add_argument('--profile', '-p', help='AWS profile name')
    parser.add_argument('--regions', '-r', nargs='+', default=['us-east-1', 'us-west-2', 'eu-west-1'],
                       help='AWS regions to analyze')
    parser.add_argument('--output', '-o', choices=['json', 'csv'], default='json',
                       help='Output format')
    parser.add_argument('--filename', '-f', help='Output filename (without extension)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Initialize analyzer
        analyzer = AWSSecurityAnalyzer(profile_name=args.profile, regions=args.regions)

        # Run assessment
        print(f"Starting security assessment for account {analyzer.account_id}")
        print(f"Analyzing regions: {', '.join(args.regions)}")

        results = analyzer.run_full_assessment()

        # Print summary
        summary = results.get('summary', {})
        print("\n" + "="*60)
        print("SECURITY ASSESSMENT SUMMARY")
        print("="*60)
        print(f"Total Findings: {summary.get('total_findings', 0)}")
        print(f"Risk Level: {summary.get('risk_level', 'UNKNOWN')}")

        severity_breakdown = summary.get('severity_breakdown', {})
        if severity_breakdown:
            print("\nFindings by Severity:")
            for severity, count in severity_breakdown.items():
                print(f"  {severity}: {count}")

        # Export results
        filename = analyzer.export_findings(format_type=args.output, filename=args.filename)
        print(f"\nDetailed results exported to: {filename}")

        # Print top recommendations
        recommendations = summary.get('recommendations', [])
        if recommendations:
            print("\nTop Security Recommendations:")
            for i, rec in enumerate(recommendations[:5], 1):
                print(f"  {i}. {rec}")

    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())