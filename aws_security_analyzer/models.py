"""
Data models for AWS Security Analyzer
"""

from dataclasses import dataclass


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