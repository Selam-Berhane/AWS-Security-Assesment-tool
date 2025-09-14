# AWS Security Posture Assessment Tool

A comprehensive security assessment tool for AWS environments that analyzes your cloud infrastructure and provides detailed security findings with remediation guidance.

## Features

- **Multi-Account Security Analysis**: Analyze security posture across multiple AWS accounts
- **IAM Policy Evaluation**: Assess IAM policies for overprivileged access and security risks
- **Network Security Assessment**: Evaluate VPC configurations, security groups, and network controls
- **Compliance Checking**: Verify compliance against CIS benchmarks and AWS best practices
- **Security Services Analysis**: Check configuration of GuardDuty, Config, CloudTrail, and Security Hub
- **Cost Optimization**: Identify unused security resources that are incurring costs
- **Detailed Reporting**: Generate comprehensive reports in JSON, CSV, and HTML formats
- **Risk Scoring**: Calculate security scores and risk levels based on findings

## Installation

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

## Usage

### Command Line Interface

Basic usage:
```bash
python aws_security_posture_tool.py
```

With specific AWS profile and regions:
```bash
python aws_security_posture_tool.py --profile my-aws-profile --regions us-east-1 us-west-2 eu-west-1
```

Export results to CSV:
```bash
python aws_security_posture_tool.py --output csv --filename my-security-assessment
```

Verbose logging:
```bash
python aws_security_posture_tool.py --verbose
```

### Command Line Options

- `--profile, -p`: AWS profile name to use
- `--regions, -r`: AWS regions to analyze (default: us-east-1, us-west-2, eu-west-1)
- `--output, -o`: Output format - json or csv (default: json)
- `--filename, -f`: Output filename without extension
- `--verbose, -v`: Enable verbose logging

### Programmatic Usage

```python
from aws_security_posture_tool import AWSSecurityAnalyzer

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

## Changelog

### Version 1.0.0
- Initial release with comprehensive security analysis
- Support for multi-region assessment
- CIS benchmark compliance checking
- Cost optimization recommendations
- Multiple output formats (JSON, CSV, HTML)

## Support

For issues, questions, or contributions, please open an issue on GitHub or contact the author.

## Disclaimer

This tool is provided as-is for security assessment purposes. Users are responsible for ensuring they have appropriate permissions to run security assessments in their AWS environments. Always follow your organization's security policies and procedures.