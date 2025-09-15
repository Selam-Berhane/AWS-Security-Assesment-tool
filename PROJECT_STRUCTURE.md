# AWS Security Analyzer - Project Structure

## Overview
The AWS Security Analyzer has been refactored into a modular architecture with separated concerns and clear interfaces between components.

## Project Structure

```
AWS-Security-Assessment-tool/
│
├── aws_security_analyzer/           # Main package
│   ├── __init__.py                 # Package initialization and exports
│   ├── models.py                   # Data models (SecurityFinding)
│   ├── config.py                   # Configuration settings
│   ├── credential_manager.py       # IAM credential report handling
│   ├── iam_analyzer.py            # IAM security analysis
│   ├── network_analyzer.py        # Network/VPC security analysis
│   ├── services_analyzer.py       # AWS security services analysis
│   ├── compliance_checker.py      # Compliance standards checking
│   └── main_analyzer.py           # Main coordinator class
│
├── aws_security_tool.py           # CLI entry point
├── aws_security_posture_tool.py   # Original monolithic file (for reference)
├── requirements.txt               # Python dependencies
├── README.md                      # Project documentation
├── .gitignore                     # Git ignore rules
└── PROJECT_STRUCTURE.md          # This file
```

## Module Descriptions

### Core Package (`aws_security_analyzer/`)

#### `__init__.py`
- Package initialization
- Exports all public classes and functions
- Version information

#### `models.py`
- **SecurityFinding**: Data class for security findings
- Standardized data structures across the application

#### `config.py`
- Application configuration settings
- Default values and thresholds
- Easy customization point for different environments

#### `credential_manager.py`
- **CredentialReportManager**: Handles IAM credential reports
- Features:
  - Report generation and caching (5-minute cache)
  - CSV parsing and data structure conversion
  - Error handling and retry logic

#### `iam_analyzer.py`
- **IAMAnalyzer**: IAM security analysis
- Features:
  - User analysis (console access, MFA)
  - Access key management and usage tracking
  - Policy risk scoring and analysis
  - Root account security checks

#### `network_analyzer.py`
- **NetworkAnalyzer**: Network and VPC security
- Features:
  - Security group analysis
  - VPC flow logs verification
  - EBS encryption checking
  - RDS public accessibility detection

#### `services_analyzer.py`
- **SecurityServicesAnalyzer**: AWS security services
- Features:
  - GuardDuty status checking
  - AWS Config analysis
  - CloudTrail configuration review
  - Multi-region service analysis

#### `compliance_checker.py`
- **ComplianceChecker**: Standards compliance
- Features:
  - CIS benchmark checking
  - Password policy validation
  - Credential usage analysis
  - Compliance scoring

#### `main_analyzer.py`
- **AWSSecurityAnalyzer**: Main coordinator
- Features:
  - Orchestrates all analysis modules
  - Parallel processing coordination
  - Results aggregation and summary generation
  - Export functionality

### CLI Interface

#### `aws_security_tool.py`
- Main command-line interface
- Argument parsing and validation
- Results formatting and display
- Error handling and logging

## Usage Examples

### Basic Usage
```bash
# Run with default settings
python aws_security_tool.py

# Specify AWS profile and regions
python aws_security_tool.py --profile production --regions us-east-1 us-west-2

# Export to CSV
python aws_security_tool.py --output csv --filename security-assessment
```

### Programmatic Usage
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
```

### Individual Module Usage
```python
from aws_security_analyzer import IAMAnalyzer, CredentialReportManager
import boto3

session = boto3.Session(profile_name='my-profile')
cred_manager = CredentialReportManager(session)
iam_analyzer = IAMAnalyzer(session, cred_manager)

# Run only IAM analysis
iam_results = iam_analyzer.analyze_iam_security()
```

## Configuration

### Environment Variables
```bash
export AWS_PROFILE=my-profile
export AWS_DEFAULT_REGION=us-east-1
```

### Configuration File (`config.py`)
```python
# Modify thresholds
ACCESS_KEY_UNUSED_DAYS = 60  # Instead of default 90
POLICY_HIGH_RISK_THRESHOLD = 9  # Instead of default 8
```

## Dependencies

### Required Packages
- `boto3>=1.26.0` - AWS SDK
- `botocore>=1.29.0` - AWS core libraries

### Optional Development Tools
```bash
pip install pytest pytest-cov black flake8 mypy
```

## Testing

### Unit Tests (Future)
```bash
# Run tests
pytest tests/

# Coverage report
pytest --cov=aws_security_analyzer tests/
```

### Integration Tests (Future)
```bash
# Test against real AWS account
pytest tests/integration/ --aws-profile test-account
```

## Development Workflow

### Adding New Analyzers
1. Create new analyzer class in separate file
2. Follow existing patterns for error handling and logging
3. Add imports to `__init__.py`
4. Integrate with main analyzer
5. Add configuration options to `config.py`

### Example New Analyzer
```python
# aws_security_analyzer/s3_analyzer.py
class S3Analyzer:
    def __init__(self, session: boto3.Session):
        self.session = session

    def analyze_s3_security(self) -> Dict[str, Any]:
        # Implementation here
        pass
```

## Benefits of Modular Structure

### Maintainability
- Each module has single responsibility
- Clear interfaces between components
- Easy to understand and modify individual parts

### Testability
- Each class can be unit tested independently
- Mock-friendly interfaces
- Isolated failure points

### Extensibility
- Easy to add new analysis modules
- Configuration-driven behavior
- Plugin-like architecture

### Performance
- Parallel processing capabilities
- Efficient resource sharing
- Caching where appropriate

### Code Quality
- Eliminated code duplication
- Consistent error handling
- Better logging and debugging

## Migration from Monolithic Version

### Backwards Compatibility
- Same CLI interface
- Same output formats
- Same functionality

### Improvements
- Better error handling
- Improved performance
- More maintainable code
- Easier testing

### Breaking Changes
- None - fully compatible with existing usage

## Future Enhancements

### Planned Features
1. **Enhanced Reporting**
   - HTML report generation
   - PDF export capabilities
   - Dashboard integration

2. **Additional Analyzers**
   - S3 security analysis
   - Lambda security review
   - ECS/EKS security checks

3. **Advanced Features**
   - Custom rule engine
   - Policy simulation
   - Remediation automation

4. **Integration**
   - CI/CD pipeline integration
   - SIEM integration
   - API endpoint for programmatic access

## Support and Contribution

### Getting Help
- Check documentation in individual module files
- Review example usage in `aws_security_tool.py`
- Enable verbose logging for debugging

### Contributing
1. Follow existing code patterns
2. Add appropriate logging
3. Include error handling
4. Update documentation
5. Test thoroughly

This modular structure provides a solid foundation for maintaining and extending the AWS Security Analyzer while preserving all existing functionality.