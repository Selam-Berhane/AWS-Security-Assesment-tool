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

import boto3
import json
import csv
import datetime
import logging
import argparse
import concurrent.futures
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import csv
import re

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
    
class AWSSecurityAnalyzer:
    """Main class for AWS security analysis"""
    
    def __init__(self, profile_name: Optional[str] = None, regions: List[str] = None):
        """Initialize the analyzer with AWS session and regions"""
        self.session = boto3.Session(profile_name=profile_name)
        self.regions = regions or ['us-east-1', 'us-west-2', 'eu-west-1']
        self.findings: List[SecurityFinding] = []
        self.account_id = self._get_account_id()
        
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
            users = iam.list_users()['Users']
            for user in users:
                username = user['UserName']
                
                # Check for console access without MFA
                try:
                    login_profile = iam.get_login_profile(UserName=username)
                    findings['users_with_console_access'].append(username)
                    
                    # Check MFA devices
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        findings['users_without_mfa'].append(username)
                        self._add_finding(
                            severity="HIGH",
                            resource_type="IAM::User",
                            resource_id=username,
                            finding_type="MFA_NOT_ENABLED",
                            description=f"User {username} has console access but no MFA enabled",
                            remediation="Enable MFA for this user account"
                        )
                except iam.exceptions.NoSuchEntityException:
                    pass
                
                # Analyze access keys
                access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                for key in access_keys:
                    key_id = key['AccessKeyId']
                    last_used = self._get_access_key_last_used(key_id)
                    if self._is_key_unused(last_used):
                        findings['unused_access_keys'].append({
                            'user': username,
                            'key_id': key_id,
                            'last_used': last_used
                        })
                        self._add_finding(
                            severity="MEDIUM",
                            resource_type="IAM::AccessKey",
                            resource_id=key_id,
                            finding_type="UNUSED_ACCESS_KEY",
                            description=f"Access key {key_id} for user {username} appears unused",
                            remediation="Consider deactivating or deleting unused access keys"
                        )
            
            # Analyze IAM policies for overprivileged access
            policies = iam.list_policies(Scope='Local')['Policies']
            for policy in policies:
                policy_doc = self._get_policy_document(policy['Arn'])
                if policy_doc:
                    risk_score = self._analyze_policy_risk(policy_doc)
                    if risk_score > 7:  # High risk threshold
                        findings['overprivileged_policies'].append({
                            'policy_name': policy['PolicyName'],
                            'arn': policy['Arn'],
                            'risk_score': risk_score
                        })
                        self._add_finding(
                            severity="HIGH" if risk_score > 8 else "MEDIUM",
                            resource_type="IAM::Policy",
                            resource_id=policy['PolicyName'],
                            finding_type="OVERPRIVILEGED_POLICY",
                            description=f"Policy {policy['PolicyName']} has high privilege risk (score: {risk_score})",
                            remediation="Review and apply principle of least privilege"
                        )
            
            # Check root account security
            root_findings = self._analyze_root_account_security()
            findings['root_account_issues'] = root_findings
            
        except Exception as e:
            logger.error(f"IAM analysis failed: {e}")
        
        return findings
    
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
                ec2 = self.session.client('ec2', region_name=region)
                rds = self.session.client('rds', region_name=region)
                
                # Analyze Security Groups
                security_groups = ec2.describe_security_groups()['SecurityGroups']
                for sg in security_groups:
                    if self._has_open_access(sg):
                        findings['open_security_groups'].append({
                            'group_id': sg['GroupId'],
                            'group_name': sg['GroupName'],
                            'region': region,
                            'risky_rules': self._get_risky_rules(sg)
                        })
                        self._add_finding(
                            severity="HIGH",
                            resource_type="EC2::SecurityGroup",
                            resource_id=sg['GroupId'],
                            finding_type="OVERLY_PERMISSIVE_SG",
                            description=f"Security group {sg['GroupId']} has overly permissive rules",
                            remediation="Restrict access to specific IP ranges and ports",
                            region=region
                        )
                
                # Check VPC Flow Logs
                vpcs = ec2.describe_vpcs()['Vpcs']
                for vpc in vpcs:
                    if not self._has_flow_logs_enabled(vpc['VpcId'], region):
                        findings['vpc_flow_logs_disabled'].append({
                            'vpc_id': vpc['VpcId'],
                            'region': region
                        })
                        self._add_finding(
                            severity="MEDIUM",
                            resource_type="EC2::VPC",
                            resource_id=vpc['VpcId'],
                            finding_type="FLOW_LOGS_DISABLED",
                            description=f"VPC {vpc['VpcId']} does not have flow logs enabled",
                            remediation="Enable VPC Flow Logs for network monitoring",
                            region=region
                        )
                
                # Check EBS encryption
                volumes = ec2.describe_volumes()['Volumes']
                for volume in volumes:
                    if not volume.get('Encrypted', False):
                        findings['unencrypted_ebs_volumes'].append({
                            'volume_id': volume['VolumeId'],
                            'region': region,
                            'state': volume['State']
                        })
                        self._add_finding(
                            severity="MEDIUM",
                            resource_type="EC2::Volume",
                            resource_id=volume['VolumeId'],
                            finding_type="UNENCRYPTED_EBS",
                            description=f"EBS volume {volume['VolumeId']} is not encrypted",
                            remediation="Enable EBS encryption for data at rest protection",
                            region=region
                        )
                
                # Check RDS instances
                try:
                    db_instances = rds.describe_db_instances()['DBInstances']
                    for db in db_instances:
                        if db.get('PubliclyAccessible', False):
                            findings['public_rds_instances'].append({
                                'db_identifier': db['DBInstanceIdentifier'],
                                'region': region,
                                'engine': db['Engine']
                            })
                            self._add_finding(
                                severity="HIGH",
                                resource_type="RDS::DBInstance",
                                resource_id=db['DBInstanceIdentifier'],
                                finding_type="PUBLIC_RDS_INSTANCE",
                                description=f"RDS instance {db['DBInstanceIdentifier']} is publicly accessible",
                                remediation="Disable public accessibility for RDS instances",
                                region=region
                            )
                except Exception as e:
                    logger.warning(f"Failed to analyze RDS in {region}: {e}")
                    
            except Exception as e:
                logger.error(f"Network analysis failed for region {region}: {e}")
        
        return findings
    
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
                # GuardDuty analysis
                guardduty = self.session.client('guardduty', region_name=region)
                try:
                    detectors = guardduty.list_detectors()['DetectorIds']
                    if detectors:
                        detector_details = guardduty.get_detector(DetectorId=detectors[0])
                        findings['guardduty_status'][region] = {
                            'enabled': detector_details['Status'] == 'ENABLED',
                            'finding_frequency': detector_details.get('FindingPublishingFrequency', 'UNKNOWN')
                        }
                    else:
                        findings['guardduty_status'][region] = {'enabled': False}
                        self._add_finding(
                            severity="HIGH",
                            resource_type="GuardDuty::Detector",
                            resource_id=f"guardduty-{region}",
                            finding_type="GUARDDUTY_DISABLED",
                            description=f"GuardDuty is not enabled in region {region}",
                            remediation="Enable GuardDuty for threat detection",
                            region=region
                        )
                except Exception:
                    findings['guardduty_status'][region] = {'enabled': False, 'error': True}
                
                # Config analysis
                config = self.session.client('config', region_name=region)
                try:
                    config_recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
                    findings['config_status'][region] = {
                        'enabled': len(config_recorders) > 0,
                        'recorder_count': len(config_recorders)
                    }
                    if not config_recorders:
                        self._add_finding(
                            severity="MEDIUM",
                            resource_type="Config::ConfigurationRecorder",
                            resource_id=f"config-{region}",
                            finding_type="CONFIG_DISABLED",
                            description=f"AWS Config is not enabled in region {region}",
                            remediation="Enable AWS Config for compliance monitoring",
                            region=region
                        )
                except Exception:
                    findings['config_status'][region] = {'enabled': False, 'error': True}
                
                # CloudTrail analysis (global service, check once)
                if region == self.regions[0]:
                    cloudtrail = self.session.client('cloudtrail', region_name=region)
                    try:
                        trails = cloudtrail.describe_trails()['trailList']
                        global_trails = [t for t in trails if t.get('IsMultiRegionTrail', False)]
                        findings['cloudtrail_status'] = {
                            'global_trails': len(global_trails),
                            'total_trails': len(trails),
                            'has_global_logging': len(global_trails) > 0
                        }
                        if not global_trails:
                            self._add_finding(
                                severity="HIGH",
                                resource_type="CloudTrail::Trail",
                                resource_id="cloudtrail-global",
                                finding_type="NO_GLOBAL_CLOUDTRAIL",
                                description="No multi-region CloudTrail is configured",
                                remediation="Configure a multi-region CloudTrail for comprehensive logging",
                                region="global"
                            )
                    except Exception:
                        findings['cloudtrail_status'] = {'enabled': False, 'error': True}
                
            except Exception as e:
                logger.error(f"Security services analysis failed for region {region}: {e}")
        
        return findings
    
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
        
        # Add findings for failed compliance checks
        for check_name, result in cis_checks.items():
            if not result.get('compliant', False):
                self._add_finding(
                    severity=result.get('severity', 'MEDIUM'),
                    resource_type="Compliance::Check",
                    resource_id=check_name,
                    finding_type="COMPLIANCE_VIOLATION",
                    description=result.get('description', f'Failed compliance check: {check_name}'),
                    remediation=result.get('remediation', 'Review and implement compliance requirements'),
                    region="global"
                )
        
        return compliance_results
    
    def generate_cost_optimization_report(self) -> Dict[str, Any]:
        """Generate security-related cost optimization recommendations"""
        logger.info("Generating cost optimization recommendations...")
        cost_findings = {
            'unused_security_groups': [],
            'unattached_eips': [],
            'oversized_cloudtrail_logs': [],
            'unused_kms_keys': []
        }
        
        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                
                # Find unused security groups
                sgs = ec2.describe_security_groups()['SecurityGroups']
                instances = ec2.describe_instances()['Reservations']
                used_sgs = set()
                
                for reservation in instances:
                    for instance in reservation['Instances']:
                        for sg in instance.get('SecurityGroups', []):
                            used_sgs.add(sg['GroupId'])
                
                for sg in sgs:
                    if sg['GroupId'] not in used_sgs and sg['GroupName'] != 'default':
                        cost_findings['unused_security_groups'].append({
                            'group_id': sg['GroupId'],
                            'group_name': sg['GroupName'],
                            'region': region
                        })
                
                # Find unattached Elastic IPs
                eips = ec2.describe_addresses()['Addresses']
                for eip in eips:
                    if 'InstanceId' not in eip and 'NetworkInterfaceId' not in eip:
                        cost_findings['unattached_eips'].append({
                            'allocation_id': eip['AllocationId'],
                            'public_ip': eip['PublicIp'],
                            'region': region
                        })
                        self._add_finding(
                            severity="LOW",
                            resource_type="EC2::EIP",
                            resource_id=eip['AllocationId'],
                            finding_type="UNUSED_EIP",
                            description=f"Elastic IP {eip['PublicIp']} is not attached and incurring charges",
                            remediation="Release unused Elastic IP addresses to reduce costs",
                            region=region
                        )
                
            except Exception as e:
                logger.error(f"Cost optimization analysis failed for region {region}: {e}")
        
        return cost_findings
    
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
            'cost_optimization': {},
            'summary': {}
        }
        
        try:
            # Run analysis modules in parallel for efficiency
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
            
            # Run cost optimization separately (not critical for security)
            assessment_results['cost_optimization'] = self.generate_cost_optimization_report()
            
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
    
    # Helper methods
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
    
    def _get_access_key_last_used(self, access_key_id: str) -> Optional[datetime.datetime]:
        """Get last used date for access key"""
        try:
            iam = self.session.client('iam')
            response = iam.get_access_key_last_used(AccessKeyId=access_key_id)
            return response.get('AccessKeyLastUsed', {}).get('LastUsedDate')
        except Exception:
            return None
    
    def _is_key_unused(self, last_used: Optional[datetime.datetime], days_threshold: int = 90) -> bool:
        """Check if access key is unused based on threshold"""
        if not last_used:
            return True
        days_since_used = (datetime.datetime.now(datetime.timezone.utc) - last_used).days
        return days_since_used > days_threshold
    
    def _get_policy_document(self, policy_arn: str) -> Optional[Dict]:
        """Get IAM policy document"""
        try:
            iam = self.session.client('iam')
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
                
                # Check for wildcard permissions
                if '*' in actions:
                    risk_score += 4
                elif any('*' in action for action in actions):
                    risk_score += 2
                
                # Check for wildcard resources
                if '*' in resources:
                    risk_score += 3
                
                # Check for dangerous actions
                dangerous_actions = ['iam:*', 'ec2:*', 's3:*', 'sts:AssumeRole']
                if any(action in dangerous_actions for action in actions):
                    risk_score += 2
        
        return min(risk_score, 10)  # Cap at 10
    
    def _analyze_root_account_security(self) -> List[Dict]:
        """Analyze root account security"""
        findings = []
        try:
            # This would require additional AWS API calls and credential report analysis
            # For brevity, returning placeholder structure
            findings.append({
                'check': 'root_mfa',
                'status': 'unknown',
                'recommendation': 'Enable MFA on root account'
            })
        except Exception as e:
            logger.error(f"Root account analysis failed: {e}")
        return findings
    
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
        # Check for open access (0.0.0.0/0 or ::/0)
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') in ['0.0.0.0/0']:
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
    
    def _has_flow_logs_enabled(self, vpc_id: str, region: str) -> bool:
        """Check if VPC has flow logs enabled"""
        try:
            ec2 = self.session.client('ec2', region_name=region)
            flow_logs = ec2.describe_flow_logs(
                Filters=[
                    {'Name': 'resource-id', 'Values': [vpc_id]},
                    {'Name': 'resource-type', 'Values': ['VPC']}
                ]
            )['FlowLogs']
            return len(flow_logs) > 0
        except Exception:
            return False

    def _get_credential_report(self) -> Optional[List[Dict[str, str]]]:
        """Get IAM credential report data"""
        try:
            iam = self.session.client('iam')

            # Generate credential report (this may take a few seconds)
            try:
                iam.generate_credential_report()

                # Wait for report generation and retrieve it
                import time
                for _ in range(10):  # Wait up to 10 seconds
                    try:
                        response = iam.get_credential_report()
                        break
                    except iam.exceptions.CredentialReportNotReadyException:
                        time.sleep(1)
                else:
                    raise Exception("Credential report generation timeout")

            except iam.exceptions.CredentialReportNotPresentException:
                # Report doesn't exist, generate it
                iam.generate_credential_report()
                time.sleep(2)  # Wait for generation
                response = iam.get_credential_report()

            # Parse the CSV credential report
            import io

            credential_data = response['Content'].decode('utf-8')
            csv_reader = csv.DictReader(io.StringIO(credential_data))

            return list(csv_reader)

        except Exception as e:
            logger.error(f"Failed to get credential report: {e}")
            return None
    
    def _check_root_mfa(self) -> Dict[str, Any]:
        """Check if root account has MFA enabled"""
        credential_report = self._get_credential_report()

        if not credential_report:
            return {
                'compliant': False,
                'description': 'Unable to retrieve credential report',
                'remediation': 'Enable MFA on root account and verify credential report access',
                'severity': 'HIGH'
            }

        # Find root account entry
        for row in credential_report:
            if row['user'] == '<root_account>':
                mfa_active = row['mfa_active'] == 'true'

                return {
                    'compliant': mfa_active,
                    'description': f'Root account MFA is {"enabled" if mfa_active else "disabled"}',
                    'remediation': 'Enable MFA on root account' if not mfa_active else 'Root MFA is properly configured',
                    'severity': 'HIGH' if not mfa_active else 'INFO',
                    'details': {
                        'mfa_active': mfa_active,
                        'password_last_used': row.get('password_last_used', 'N/A'),
                        'password_last_changed': row.get('password_last_changed', 'N/A')
                    }
                }

        # Root account not found in report
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
        credential_report = self._get_credential_report()

        if not credential_report:
            return {
                'compliant': False,
                'description': 'Unable to retrieve credential report for credential analysis',
                'remediation': 'Review and remove unused credentials manually',
                'severity': 'MEDIUM'
            }

        unused_users = []
        unused_access_keys = []
        threshold_days = 90  # Consider credentials unused after 90 days

        for row in credential_report:
            username = row['user']

            # Skip root account (handled separately)
            if username == '<root_account>':
                continue

            # Check password usage
            password_last_used = row.get('password_last_used', 'N/A')
            if password_last_used not in ['N/A', 'no_information'] and password_last_used:
                try:
                    from datetime import datetime
                    last_used_date = datetime.fromisoformat(password_last_used.replace('Z', '+00:00'))
                    days_since_used = (datetime.now(datetime.timezone.utc) - last_used_date).days

                    if days_since_used > threshold_days:
                        unused_users.append({
                            'username': username,
                            'password_last_used': password_last_used,
                            'days_since_used': days_since_used
                        })
                except (ValueError, AttributeError):
                    # Handle date parsing errors
                    pass

            # Check access key 1 usage
            access_key_1_active = row.get('access_key_1_active', 'false') == 'true'
            access_key_1_last_used = row.get('access_key_1_last_used_date', 'N/A')

            if access_key_1_active and access_key_1_last_used not in ['N/A', 'no_information'] and access_key_1_last_used:
                try:
                    last_used_date = datetime.fromisoformat(access_key_1_last_used.replace('Z', '+00:00'))
                    days_since_used = (datetime.now(datetime.timezone.utc) - last_used_date).days

                    if days_since_used > threshold_days:
                        unused_access_keys.append({
                            'username': username,
                            'access_key_last_used': access_key_1_last_used,
                            'days_since_used': days_since_used
                        })
                except (ValueError, AttributeError):
                    pass

            # Check access key 2 usage
            access_key_2_active = row.get('access_key_2_active', 'false') == 'true'
            access_key_2_last_used = row.get('access_key_2_last_used_date', 'N/A')

            if access_key_2_active and access_key_2_last_used not in ['N/A', 'no_information'] and access_key_2_last_used:
                try:
                    last_used_date = datetime.fromisoformat(access_key_2_last_used.replace('Z', '+00:00'))
                    days_since_used = (datetime.now(datetime.timezone.utc) - last_used_date).days

                    if days_since_used > threshold_days:
                        unused_access_keys.append({
                            'username': username,
                            'access_key_last_used': access_key_2_last_used,
                            'days_since_used': days_since_used
                        })
                except (ValueError, AttributeError):
                    pass

        # Generate findings for unused credentials
        for user_data in unused_users:
            self._add_finding(
                severity="MEDIUM",
                resource_type="IAM::User",
                resource_id=user_data['username'],
                finding_type="UNUSED_CONSOLE_ACCESS",
                description=f"User {user_data['username']} has not used console access in {user_data['days_since_used']} days",
                remediation="Review user necessity and consider disabling console access or removing user"
            )

        for key_data in unused_access_keys:
            self._add_finding(
                severity="MEDIUM",
                resource_type="IAM::AccessKey",
                resource_id=key_data['username'],
                finding_type="UNUSED_ACCESS_KEY",
                description=f"Access key for user {key_data['username']} has not been used in {key_data['days_since_used']} days",
                remediation="Consider rotating or removing unused access keys"
            )

        total_unused = len(unused_users) + len(unused_access_keys)

        return {
            'compliant': total_unused == 0,
            'description': f'Found {total_unused} unused credentials (users: {len(unused_users)}, access keys: {len(unused_access_keys)})',
            'remediation': 'Review and remove unused credentials to reduce security risk',
            'severity': 'HIGH' if total_unused > 5 else 'MEDIUM' if total_unused > 0 else 'INFO',
            'details': {
                'unused_users': unused_users,
                'unused_access_keys': unused_access_keys,
                'threshold_days': threshold_days
            }
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


def main():
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


# Additional utility functions and classes for enhanced functionality

class SecurityMetrics:
    """Class for calculating security metrics and KPIs"""
    
    def __init__(self, findings: List[SecurityFinding]):
        self.findings = findings
    
    def calculate_security_score(self) -> float:
        """Calculate overall security score (0-100)"""
        if not self.findings:
            return 100.0
        
        # Weight findings by severity
        severity_weights = {'HIGH': 10, 'MEDIUM': 5, 'LOW': 1}
        total_weight = sum(severity_weights.get(f.severity, 1) for f in self.findings)
        
        # Calculate score (lower findings = higher score)
        max_possible_weight = len(self.findings) * 10  # If all were HIGH
        score = max(0, 100 - (total_weight / max_possible_weight * 100))
        
        return round(score, 2)
    
    def get_improvement_areas(self) -> List[Dict[str, Any]]:
        """Identify top areas for security improvement"""
        resource_type_counts = defaultdict(int)
        
        for finding in self.findings:
            if finding.severity in ['HIGH', 'MEDIUM']:
                resource_type_counts[finding.resource_type] += 1
        
        return [
            {'resource_type': rt, 'finding_count': count}
            for rt, count in sorted(resource_type_counts.items(), 
                                  key=lambda x: x[1], reverse=True)[:5]
        ]


class ReportGenerator:
    """Generate detailed HTML and PDF reports"""
    
    def __init__(self, assessment_results: Dict[str, Any], findings: List[SecurityFinding]):
        self.results = assessment_results
        self.findings = findings
        self.metrics = SecurityMetrics(findings)
    
    def generate_html_report(self, filename: str = None) -> str:
        """Generate HTML report"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aws_security_report_{timestamp}.html"
        
        html_content = self._create_html_content()
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename
    
    def _create_html_content(self) -> str:
        """Create HTML report content"""
        summary = self.results.get('summary', {})
        security_score = self.metrics.calculate_security_score()
        improvement_areas = self.metrics.get_improvement_areas()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AWS Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #232f3e; color: white; padding: 20px; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; margin: 20px 0; }}
                .finding {{ border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; }}
                .finding.MEDIUM {{ border-left-color: #fd7e14; }}
                .finding.LOW {{ border-left-color: #28a745; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>AWS Security Assessment Report</h1>
                <p>Account: {self.results.get('account_id', 'Unknown')}</p>
                <p>Assessment Date: {self.results.get('assessment_timestamp', 'Unknown')}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Security Score:</strong> {security_score}/100</p>
                <p><strong>Total Findings:</strong> {summary.get('total_findings', 0)}</p>
                <p><strong>Risk Level:</strong> {summary.get('risk_level', 'UNKNOWN')}</p>
            </div>
            
            <h2>Findings by Severity</h2>
            <table>
                <tr><th>Severity</th><th>Count</th></tr>
        """
        
        for severity, count in summary.get('severity_breakdown', {}).items():
            html += f"<tr><td>{severity}</td><td>{count}</td></tr>"
        
        html += """
            </table>
            
            <h2>Top Areas for Improvement</h2>
            <table>
                <tr><th>Resource Type</th><th>Finding Count</th></tr>
        """
        
        for area in improvement_areas:
            html += f"<tr><td>{area['resource_type']}</td><td>{area['finding_count']}</td></tr>"
        
        html += """
            </table>
            
            <h2>Detailed Findings</h2>
        """
        
        for finding in sorted(self.findings, key=lambda x: {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x.severity, 0), reverse=True)[:20]:
            html += f"""
            <div class="finding {finding.severity}">
                <h4>[{finding.severity}] {finding.finding_type}</h4>
                <p><strong>Resource:</strong> {finding.resource_type}::{finding.resource_id}</p>
                <p><strong>Region:</strong> {finding.region}</p>
                <p><strong>Description:</strong> {finding.description}</p>
                <p><strong>Remediation:</strong> {finding.remediation}</p>
            </div>
            """
        
        html += """
            </body>
        </html>
        """
        
        return html


# Example usage and testing
if __name__ == "__main__":
    # Example of how to use the tool programmatically
    print("AWS Security Posture Analyzer")
    print("Usage examples:")
    print("  python aws_security_analyzer.py --profile my-profile --regions us-east-1 us-west-2")
    print("  python aws_security_analyzer.py --output csv --filename my-assessment")
    print("  python aws_security_analyzer.py --verbose")
    
    # Run main function
    main()