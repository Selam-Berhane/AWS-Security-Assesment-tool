"""
Network Security Analyzer

Handles VPC, security groups, and network-related security analysis
"""

import logging
from typing import Any, Dict, List

import boto3

logger = logging.getLogger(__name__)


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
                logger.info(f"Analyzing network security in region: {region}")
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
        try:
            security_groups = ec2.describe_security_groups()['SecurityGroups']
            logger.info(f"Analyzing {len(security_groups)} security groups in {region}")

            for sg in security_groups:
                if self._has_open_access(sg):
                    findings['open_security_groups'].append({
                        'group_id': sg['GroupId'],
                        'group_name': sg['GroupName'],
                        'region': region,
                        'risky_rules': self._get_risky_rules(sg)
                    })

        except Exception as e:
            logger.error(f"Security group analysis failed in {region}: {e}")

    def _check_vpc_flow_logs(self, ec2, region: str, findings: Dict[str, Any]) -> None:
        """Check VPC flow logs configuration"""
        try:
            vpcs = ec2.describe_vpcs()['Vpcs']
            logger.info(f"Checking flow logs for {len(vpcs)} VPCs in {region}")

            for vpc in vpcs:
                if not self._has_flow_logs_enabled(ec2, vpc['VpcId']):
                    findings['vpc_flow_logs_disabled'].append({
                        'vpc_id': vpc['VpcId'],
                        'region': region
                    })

        except Exception as e:
            logger.error(f"VPC flow logs check failed in {region}: {e}")

    def _check_ebs_encryption(self, ec2, region: str, findings: Dict[str, Any]) -> None:
        """Check EBS volume encryption"""
        try:
            volumes = ec2.describe_volumes()['Volumes']
            logger.info(f"Checking encryption for {len(volumes)} EBS volumes in {region}")

            for volume in volumes:
                if not volume.get('Encrypted', False):
                    findings['unencrypted_ebs_volumes'].append({
                        'volume_id': volume['VolumeId'],
                        'region': region,
                        'state': volume['State']
                    })

        except Exception as e:
            logger.error(f"EBS encryption check failed in {region}: {e}")

    def _check_rds_instances(self, region: str, findings: Dict[str, Any]) -> None:
        """Check RDS instances for public accessibility"""
        try:
            rds = self.session.client('rds', region_name=region)
            db_instances = rds.describe_db_instances()['DBInstances']
            logger.info(f"Checking {len(db_instances)} RDS instances in {region}")

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