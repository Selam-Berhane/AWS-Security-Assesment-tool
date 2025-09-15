"""
Main AWS Security Analyzer

Coordinates and orchestrates the security analysis across all modules
"""

import concurrent.futures
import csv
import datetime
import json
import logging
from collections import defaultdict
from dataclasses import asdict
from typing import Any, Dict, List, Optional

import boto3

from .compliance_checker import ComplianceChecker
from .credential_manager import CredentialReportManager
from .iam_analyzer import IAMAnalyzer
from .models import SecurityFinding
from .network_analyzer import NetworkAnalyzer
from .services_analyzer import SecurityServicesAnalyzer

logger = logging.getLogger(__name__)


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

        logger.info(f"Initialized AWS Security Analyzer for account {self.account_id}")
        logger.info(f"Analysis will cover regions: {', '.join(self.regions)}")

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
        logger.info("Starting IAM security analysis...")
        return self.iam_analyzer.analyze_iam_security()

    def analyze_network_security(self) -> Dict[str, Any]:
        """Analyze VPC and network security configurations"""
        logger.info("Starting network security analysis...")
        return self.network_analyzer.analyze_network_security()

    def analyze_security_services(self) -> Dict[str, Any]:
        """Analyze AWS security services configuration"""
        logger.info("Starting security services analysis...")
        return self.services_analyzer.analyze_security_services()

    def check_compliance_standards(self) -> Dict[str, Any]:
        """Check compliance against CIS benchmarks and AWS best practices"""
        logger.info("Starting compliance standards check...")
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
            # Run analysis modules in parallel for better performance
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
                        logger.info(f"Completed {analysis_type}")
                    except Exception as e:
                        logger.error(f"{analysis_type} failed: {e}")
                        assessment_results[analysis_type] = {'error': str(e)}

            # Generate summary
            assessment_results['summary'] = self._generate_summary()

        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            assessment_results['error'] = str(e)

        logger.info("Security assessment completed")
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

    def add_finding(self, severity: str, resource_type: str, resource_id: str,
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
        logger.debug(f"Added {severity} finding: {finding_type} for {resource_type}::{resource_id}")

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate assessment summary"""
        severity_counts = defaultdict(int)
        finding_types = defaultdict(int)

        for finding in self.findings:
            severity_counts[finding.severity] += 1
            finding_types[finding.finding_type] += 1

        summary = {
            'total_findings': len(self.findings),
            'severity_breakdown': dict(severity_counts),
            'top_finding_types': dict(sorted(finding_types.items(), key=lambda x: x[1], reverse=True)[:5]),
            'risk_level': self._calculate_risk_level(severity_counts),
            'recommendations': self._get_top_recommendations()
        }

        logger.info(f"Assessment summary: {summary['total_findings']} findings, risk level: {summary['risk_level']}")
        return summary

    def _calculate_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        high_count = severity_counts.get('HIGH', 0)
        medium_count = severity_counts.get('MEDIUM', 0)

        if high_count > 5:
            return 'CRITICAL'
        elif high_count > 0 or medium_count > 10:
            return 'HIGH'
        elif medium_count > 0:
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