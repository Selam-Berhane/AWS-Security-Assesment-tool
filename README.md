# AWS Security Posture Assessment Tool

A comprehensive security assessment tool for AWS environments that analyzes your cloud infrastructure and provides detailed security findings with remediation guidance.

Built with a **modular architecture** for better maintainability, performance, and extensibility.

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
├── aws_security_analyzer/           # Modular package
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
├── aws_security_tool.py           # Main CLI interface
├── iam-policy.json                # Required IAM permissions
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

### Command Line Interface

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

### 📋 Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--profile` | `-p` | AWS profile name | Default profile |
| `--regions` | `-r` | AWS regions to analyze | us-east-1, us-west-2, eu-west-1 |
| `--output` | `-o` | Output format (json/csv) | json |
| `--filename` | `-f` | Output filename (no extension) | Auto-generated |
| `--verbose` | `-v` | Enable verbose logging | False |

### 🐍 Programmatic Usage

#### Main API
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

## 🔐 Required AWS Permissions

The tool requires specific IAM permissions to perform security analysis. You can use the provided IAM policy file or create a custom policy.

### Quick Setup
```bash
# Use the provided IAM policy file
aws iam create-policy \
  --policy-name AWSSecurityAnalyzerPolicy \
  --policy-document file://iam-policy.json

# Attach to user or role
aws iam attach-user-policy \
  --user-name your-username \
  --policy-arn arn:aws:iam::ACCOUNT-ID:policy/AWSSecurityAnalyzerPolicy
```

### Fine-Grained Permissions (Least Privilege)
The tool uses a fine-grained IAM policy with specific conditions and resource restrictions:

#### 🎯 Core Identity
- `sts:GetCallerIdentity` - Get current AWS account information

#### 🔐 IAM Analysis (Scoped)
- **Account-Level**: `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:GetAccountPasswordPolicy`
- **User-Specific**: Limited to `arn:aws:iam::*:user/*` resources only
- **Customer Policies Only**: `iam:ListPolicies` with condition `"iam:PolicyScope": "Local"`
- **Policy Analysis**: Restricted to customer-managed policies only

#### 🌐 Network Security (Essential Only)
- `ec2:DescribeSecurityGroups` - Security group rule analysis
- `ec2:DescribeVpcs` - VPC configuration check
- `ec2:DescribeFlowLogs` - Flow logs verification
- `ec2:DescribeVolumes` - EBS encryption status
- `ec2:DescribeInstances` - Only for security group mapping
- `ec2:DescribeAddresses` - Unattached EIP detection

#### 🛡️ Security Services (Status Only)
- **GuardDuty**: `guardduty:ListDetectors`, `guardduty:GetDetector`
- **Config**: `config:DescribeConfigurationRecorders`
- **CloudTrail**: `cloudtrail:DescribeTrails`

#### 🗄️ Database & Storage (Minimal)
- **RDS**: `rds:DescribeDBInstances` - Public accessibility check only
- **S3**: `s3:GetBucketPublicAccessBlock`, `s3:ListAllMyBuckets` - Public access analysis

### Security Considerations
- ✅ **Fine-Grained Access**: Uses specific resource ARNs and conditions where possible
- ✅ **Customer Policies Only**: IAM policy analysis limited to customer-managed policies
- ✅ **No AWS Managed Policies**: Cannot access AWS-managed policy documents
- ✅ **User-Scoped IAM**: IAM user operations limited to user resources only
- ✅ **Read-Only Permissions**: Cannot modify any AWS resources
- ✅ **Audit Trail**: All API calls logged in CloudTrail
- ✅ **Minimal Footprint**: Only essential permissions for each analysis type

### Custom Policy Creation
If you prefer to create a minimal policy, here's the essential permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:List*",
        "iam:Get*",
        "ec2:Describe*",
        "rds:Describe*",
        "guardduty:List*",
        "guardduty:Get*",
        "config:Describe*",
        "cloudtrail:Describe*",
        "s3:GetBucket*"
      ],
      "Resource": "*"
    }
  ]
}
```


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

### Custom Configuration
```python
# Modify aws_security_analyzer/config.py
ACCESS_KEY_UNUSED_DAYS = 60  # Instead of default 90
POLICY_HIGH_RISK_THRESHOLD = 9  # Instead of default 8
```

## 🧪 Advanced Usage

### Parallel Analysis
```bash
# Automatically runs analyses in parallel across multiple regions
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

### Modular Design Advantages

| Aspect | Benefits |
|--------|----------|
| **File Structure** | 9 focused modules (50-200 lines each) instead of monolithic code |
| **Maintainability** | Easy to understand and modify individual components |
| **Testing** | Each module can be unit tested independently |
| **Performance** | Optimized with credential caching and parallel processing |
| **Extensibility** | Plugin-like architecture for adding new analyzers |
| **Code Reuse** | Individual modules can be used separately |

### Performance Improvements
- **Credential Report Caching**: 5-minute cache reduces API calls
- **Parallel Processing**: Concurrent analysis across regions
- **Optimized Imports**: Faster startup time
- **Memory Efficiency**: Better garbage collection

## 🚀 Getting Started

### Basic Usage
```bash
# Run security assessment
python aws_security_tool.py --profile my-profile
```

### Advanced Capabilities
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

**Import Errors**
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

### Adding New Analyzers

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

### Version 2.0.0 (Current)
- 🆕 **Modular Architecture**: Separated into focused modules
- 🚀 **Performance**: 5-minute credential report caching
- 🔧 **Configuration**: Centralized settings in config.py
- 🧪 **Testability**: Individual modules can be unit tested
- 📦 **Packaging**: Proper Python package structure
- ⚡ **Parallel Processing**: Concurrent analysis across regions

### Version 1.0.0
- Initial release with comprehensive security analysis
- Support for multi-region assessment
- CIS benchmark compliance checking
- Cost optimization recommendations
- Multiple output formats (JSON, CSV, HTML)

## 📞 Support

### Getting Help
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


## ⚠️ Disclaimer

This tool is provided as-is for security assessment purposes. Users are responsible for ensuring they have appropriate permissions to run security assessments in their AWS environments. Always follow your organization's security policies and procedures.

---

**🌟 Built with modular architecture** for better performance, maintainability, and extensibility!