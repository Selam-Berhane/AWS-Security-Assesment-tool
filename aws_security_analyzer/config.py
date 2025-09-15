"""
Configuration settings for AWS Security Analyzer
"""

# Default regions to analyze
DEFAULT_REGIONS = [
    'us-east-1',
    'us-west-2',
    'eu-west-1'
]

# Security thresholds
ACCESS_KEY_UNUSED_DAYS = 90
CREDENTIAL_UNUSED_DAYS = 90
PASSWORD_MIN_LENGTH = 14

# Risk scoring thresholds
POLICY_HIGH_RISK_THRESHOLD = 8
POLICY_MEDIUM_RISK_THRESHOLD = 7

# Compliance scoring
COMPLIANCE_HIGH_THRESHOLD = 80
COMPLIANCE_MEDIUM_THRESHOLD = 60

# Cache settings
CREDENTIAL_REPORT_CACHE_DURATION = 300  # 5 minutes

# Parallel processing
MAX_WORKERS = 4

# Output settings
DEFAULT_OUTPUT_FORMAT = 'json'

# Logging settings
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'