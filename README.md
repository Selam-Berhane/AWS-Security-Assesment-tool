# AWS Security Posture Assessment Tool

A comprehensive security assessment tool for AWS environments that analyzes your cloud infrastructure and provides detailed security findings with remediation guidance.

🆕 **Now available in two versions:**
- **Modular Architecture** (`aws_security_tool.py`) - Recommended for new users
- **Original Version** (`aws_security_posture_tool.py`) - Legacy monolithic version

## ✨ Features

- **Multi-Account Security Analysis**: Analyze security posture across multiple AWS accounts
- **IAM Policy Evaluation**: Assess IAM policies for overprivileged access and security risks
- **Network Security Assessment**: Evaluate VPC configurations, security groups, and network controls
- **Compliance Checking**: Verify compliance against CIS benchmarks and AWS best practices
- **Security Services Analysis**: Check configuration of GuardDuty, Config, CloudTrail, and Security Hub
- **Cost Optimization**: Identify unused security resources that are incurring costs
- **Detailed Reporting**: Generate comprehensive reports in JSON, CSV, and HTML formats
- **Risk Scoring**: Calculate security scores and risk levels based on findings
- **Modular Architecture**: Clean, maintainable code with separated concerns

## 📁 Project Structure

```
AWS-Security-Assessment-tool/
│
├── aws_security_analyzer/           # 🆕 Modular package
│   ├── __init__.py                 # Package exports
│   ├── models.py                   # Data models
│   ├── config.py                   # Configuration
│   ├── credential_manager.py       # Credential report handling
│   ├── iam_analyzer.py            # IAM security analysis
│   ├── network_analyzer.py        # Network security
│   ├── services_analyzer.py       # Security services
│   ├── compliance_checker.py      # Compliance checking
│   └── main_analyzer.py           # Main coordinator
│
├── aws_security_tool.py           # 🆕 Modern CLI (Recommended)
├── aws_security_posture_tool.py   # Legacy monolithic version
├── requirements.txt               # Dependencies
└── README.md                      # This file
```

## 🚀 Quick Start

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd AWS-Security-Assessment-tool
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure AWS credentials:
```bash
aws configure
# or use AWS profiles
aws configure --profile your-profile-name
```

## 📖 Usage

### 🌟 Recommended: Modern Modular CLI

```bash
# Basic usage
python aws_security_tool.py

# With specific profile and regions
python aws_security_tool.py --profile production --regions us-east-1 us-west-2

# Export to CSV with custom filename
python aws_security_tool.py --output csv --filename security-report-2024

# Verbose mode for detailed logging
python aws_security_tool.py --verbose
```

### Legacy CLI (Still Supported)

```bash
# Original version still works
python aws_security_posture_tool.py --profile my-profile
```

### 📋 Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--profile` | `-p` | AWS profile name | Default profile |
| `--regions` | `-r` | AWS regions to analyze | us-east-1, us-west-2, eu-west-1 |
| `--output` | `-o` | Output format (json/csv) | json |
| `--filename` | `-f` | Output filename (no extension) | Auto-generated |
| `--verbose` | `-v` | Enable verbose logging | False |

### 🐍 Programmatic Usage

#### Modern Modular API (Recommended)
```python
from aws_security_analyzer import AWSSecurityAnalyzer

# Initialize analyzer
analyzer = AWSSecurityAnalyzer(
    profile_name='my-profile',
    regions=['us-east-1', 'us-west-2']
)

# Run full assessment
results = analyzer.run_full_assessment()

# Export findings
filename = analyzer.export_findings(format_type='json')
print(f"Results saved to {filename}")
```

#### Individual Module Usage
```python
from aws_security_analyzer import IAMAnalyzer, CredentialReportManager
import boto3

# Use individual analyzers
session = boto3.Session(profile_name='my-profile')
cred_manager = CredentialReportManager(session)
iam_analyzer = IAMAnalyzer(session, cred_manager)

# Run specific analysis
iam_results = iam_analyzer.analyze_iam_security()
```

#### Legacy API (Still Supported)
```python
from aws_security_posture_tool import AWSSecurityAnalyzer

# Same interface as before
analyzer = AWSSecurityAnalyzer(profile_name='my-profile')
results = analyzer.run_full_assessment()
```

## Security Checks

### IAM Security Analysis
- Users with console access without MFA
- Unused and expired access keys
- Overprivileged IAM policies
- Root account security issues
- Policy risk scoring

### Network Security Analysis
- Overly permissive security groups
- Unencrypted EBS volumes
- Publicly accessible RDS instances
- VPC Flow Logs configuration
- Network ACL analysis

### Security Services Analysis
- Amazon GuardDuty status
- AWS Config configuration
- CloudTrail logging setup
- AWS Security Hub enablement

### Compliance Checks
- CIS Benchmark compliance
- AWS Foundational Security Standards
- Password policy compliance
- Access key rotation policies

### Cost Optimization
- Unused security groups
- Unattached Elastic IP addresses
- Oversized CloudTrail logs
- Unused KMS keys

## Output Formats

### JSON Output
Detailed structured data suitable for programmatic processing:
```json
{
  "account_id": "123456789012",
  "assessment_timestamp": "2024-01-15T10:30:00Z",
  "regions_analyzed": ["us-east-1", "us-west-2"],
  "findings": [...],
  "summary": {
    "total_findings": 25,
    "risk_level": "HIGH",
    "severity_breakdown": {
      "HIGH": 5,
      "MEDIUM": 15,
      "LOW": 5
    }
  }
}
```

### CSV Output
Tabular format for spreadsheet analysis with columns:
- Severity
- Resource Type
- Resource ID
- Finding Type
- Description
- Remediation
- Region
- Account ID
- Compliance Status

### HTML Report
Comprehensive visual report with:
- Executive summary
- Security score calculation
- Findings organized by severity
- Top improvement areas
- Detailed remediation guidance

## Requirements

- Python 3.7+
- boto3 >= 1.26.0
- botocore >= 1.29.0
- Valid AWS credentials with appropriate permissions

## Required AWS Permissions

The tool requires the following AWS permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*",
        "ec2:Describe*",
        "rds:Describe*",
        "guardduty:List*",
        "guardduty:Get*",
        "config:Describe*",
        "cloudtrail:Describe*",
        "sts:GetCallerIdentity",
        "s3:GetBucketPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

## Security Considerations

- The tool only requires read permissions and does not modify any AWS resources
- Credentials are handled securely through boto3 session management
- All API calls are logged for audit purposes
- No sensitive data is exposed in output files

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Selam Berhane Gebreananeya

## 🔧 Configuration

### Environment Variables
```bash
export AWS_PROFILE=my-profile
export AWS_DEFAULT_REGION=us-east-1
```

### Custom Configuration (Modular Version)
```python
# Modify aws_security_analyzer/config.py
ACCESS_KEY_UNUSED_DAYS = 60  # Instead of default 90
POLICY_HIGH_RISK_THRESHOLD = 9  # Instead of default 8
```

## 🧪 Advanced Usage

### Parallel Analysis
```bash
# The modular version automatically runs analyses in parallel
python aws_security_tool.py --regions us-east-1 us-west-2 eu-west-1 eu-central-1
```

### Custom Risk Thresholds
```python
from aws_security_analyzer import config

# Modify thresholds before analysis
config.ACCESS_KEY_UNUSED_DAYS = 60
config.POLICY_HIGH_RISK_THRESHOLD = 9
```

### Exit Codes
The tool returns different exit codes based on risk level:
- `0`: Low risk or success
- `1`: Medium risk
- `2`: High or Critical risk

## 🏗️ Architecture Benefits

### Modular vs Monolithic

| Aspect | Legacy Version | Modular Version |
|--------|---------------|-----------------|
| **File Structure** | Single 1000+ line file | 9 focused modules (50-200 lines each) |
| **Maintainability** | Difficult | Easy |
| **Testing** | Hard to unit test | Each module testable |
| **Performance** | Good | Better (optimized caching) |
| **Extensibility** | Monolithic changes | Plugin-like additions |
| **Code Reuse** | None | Individual modules usable |

### Performance Improvements
- **Credential Report Caching**: 5-minute cache reduces API calls
- **Parallel Processing**: Concurrent analysis across regions
- **Optimized Imports**: Faster startup time
- **Memory Efficiency**: Better garbage collection

## 🚀 Migration Guide

### From Legacy to Modular

**No Breaking Changes** - Both versions work identically:

```bash
# Old way (still works)
python aws_security_posture_tool.py --profile test

# New way (recommended)
python aws_security_tool.py --profile test
```

**New Capabilities** - Modular version adds:
```python
# Use individual components
from aws_security_analyzer import NetworkAnalyzer

# Custom analyzers
from aws_security_analyzer.iam_analyzer import IAMAnalyzer
```

## 📊 Example Output

### Console Summary
```
==========================================
SECURITY ASSESSMENT SUMMARY
==========================================
Account ID: 123456789012
Assessment Time: 2024-01-15T10:30:00Z
Regions Analyzed: us-east-1, us-west-2
Total Findings: 25
Risk Level: HIGH

Findings by Severity:
  HIGH: 5
  MEDIUM: 15
  LOW: 5

Top Security Recommendations:
  1. Enable MFA on all user accounts with console access
  2. Configure multi-region CloudTrail logging
  3. Enable GuardDuty in all regions
```

### Detailed JSON Export
```json
{
  "account_id": "123456789012",
  "assessment_timestamp": "2024-01-15T10:30:00Z",
  "regions_analyzed": ["us-east-1", "us-west-2"],
  "iam_analysis": {
    "users_without_mfa": ["user1", "user2"],
    "overprivileged_policies": [...]
  },
  "summary": {
    "total_findings": 25,
    "risk_level": "HIGH",
    "compliance_score": 65.5
  }
}
```

## 🔍 Troubleshooting

### Common Issues

**Import Errors (Modular Version)**
```bash
# Ensure you're in the project directory
cd AWS-Security-Assessment-tool
python aws_security_tool.py
```

**AWS Permissions**
```bash
# Test AWS access
aws sts get-caller-identity --profile your-profile
```

**Verbose Mode for Debugging**
```bash
python aws_security_tool.py --verbose
```

## 🤝 Contributing

### Adding New Analyzers (Modular Version)

1. Create new analyzer file:
```python
# aws_security_analyzer/s3_analyzer.py
class S3Analyzer:
    def __init__(self, session):
        self.session = session

    def analyze_s3_security(self):
        # Implementation
        pass
```

2. Add to main analyzer:
```python
# aws_security_analyzer/main_analyzer.py
from .s3_analyzer import S3Analyzer

class AWSSecurityAnalyzer:
    def __init__(self, ...):
        self.s3_analyzer = S3Analyzer(self.session)
```

3. Update package exports:
```python
# aws_security_analyzer/__init__.py
from .s3_analyzer import S3Analyzer
```

## 📈 Changelog

### Version 2.0.0 (Latest - Modular)
- 🆕 **Modular Architecture**: Separated into focused modules
- 🚀 **Performance**: 5-minute credential report caching
- 🔧 **Configuration**: Centralized settings in config.py
- 🧪 **Testability**: Individual modules can be unit tested
- 📦 **Packaging**: Proper Python package structure
- 🔄 **Backwards Compatibility**: Legacy version still supported

### Version 1.0.0 (Legacy)
- Initial release with comprehensive security analysis
- Support for multi-region assessment
- CIS benchmark compliance checking
- Cost optimization recommendations
- Multiple output formats (JSON, CSV, HTML)

## 📞 Support

### Getting Help
- 📖 Check [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for detailed architecture
- 🐛 Enable `--verbose` for debugging
- 📋 Review individual module documentation

### Reporting Issues
- 🔗 Open issues on GitHub
- 📧 Contact: Selam Berhane Gebreananeya
- 📝 Include verbose output and AWS region info

### Contributing
1. Fork the repository
2. Create a feature branch
3. Follow existing code patterns
4. Add appropriate tests
5. Submit a pull request

## ⚖️ License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided as-is for security assessment purposes. Users are responsible for ensuring they have appropriate permissions to run security assessments in their AWS environments. Always follow your organization's security policies and procedures.

---

**🌟 Recommended**: Use the modular version (`aws_security_tool.py`) for better performance, maintainability, and future updates!