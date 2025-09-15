"""
AWS Security Analyzer Package

A comprehensive security assessment tool for AWS environments
"""

from .models import SecurityFinding
from .credential_manager import CredentialReportManager
from .iam_analyzer import IAMAnalyzer
from .network_analyzer import NetworkAnalyzer
from .services_analyzer import SecurityServicesAnalyzer
from .compliance_checker import ComplianceChecker
from .main_analyzer import AWSSecurityAnalyzer

__version__ = "1.0.0"
__author__ = "Selam Berhane Gebreananeya"

__all__ = [
    'SecurityFinding',
    'CredentialReportManager',
    'IAMAnalyzer',
    'NetworkAnalyzer',
    'SecurityServicesAnalyzer',
    'ComplianceChecker',
    'AWSSecurityAnalyzer'
]