#!/usr/bin/env python3
"""
AWS Security Posture Assessment Tool - Main CLI Script

A comprehensive security assessment tool for AWS environments using modular architecture.

Usage:
    python aws_security_tool.py --profile my-profile --regions us-east-1 us-west-2
    python aws_security_tool.py --output csv --filename my-assessment

Author: Selam Berhane Gebreananeya
"""

import argparse
import logging
import sys

from aws_security_analyzer import AWSSecurityAnalyzer


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application"""
    log_level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    # Reduce noise from boto3
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)


def print_assessment_summary(results: dict) -> None:
    """Print assessment summary to console"""
    summary = results.get('summary', {})

    print("\n" + "="*60)
    print("SECURITY ASSESSMENT SUMMARY")
    print("="*60)
    print(f"Account ID: {results.get('account_id', 'Unknown')}")
    print(f"Assessment Time: {results.get('assessment_timestamp', 'Unknown')}")
    print(f"Regions Analyzed: {', '.join(results.get('regions_analyzed', []))}")
    print(f"Total Findings: {summary.get('total_findings', 0)}")
    print(f"Risk Level: {summary.get('risk_level', 'UNKNOWN')}")

    # Severity breakdown
    severity_breakdown = summary.get('severity_breakdown', {})
    if severity_breakdown:
        print("\nFindings by Severity:")
        for severity, count in severity_breakdown.items():
            print(f"  {severity}: {count}")

    # Top finding types
    top_findings = summary.get('top_finding_types', {})
    if top_findings:
        print("\nTop Finding Types:")
        for finding_type, count in list(top_findings.items())[:3]:
            print(f"  {finding_type}: {count}")


def print_recommendations(results: dict) -> None:
    """Print security recommendations"""
    recommendations = results.get('summary', {}).get('recommendations', [])
    if recommendations:
        print("\nTop Security Recommendations:")
        for i, rec in enumerate(recommendations[:5], 1):
            print(f"  {i}. {rec}")


def main() -> int:
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(
        description='AWS Security Posture Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --profile my-aws-profile
  %(prog)s --regions us-east-1 us-west-2 eu-west-1
  %(prog)s --output csv --filename security-report
  %(prog)s --verbose
        """
    )

    parser.add_argument(
        '--profile', '-p',
        help='AWS profile name to use for authentication'
    )

    parser.add_argument(
        '--regions', '-r',
        nargs='+',
        default=['us-east-1', 'us-west-2', 'eu-west-1'],
        help='AWS regions to analyze (default: %(default)s)'
    )

    parser.add_argument(
        '--output', '-o',
        choices=['json', 'csv'],
        default='json',
        help='Output format for detailed results (default: %(default)s)'
    )

    parser.add_argument(
        '--filename', '-f',
        help='Output filename without extension (auto-generated if not specified)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='AWS Security Analyzer 1.0.0'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    try:
        # Initialize analyzer
        logger.info("Initializing AWS Security Analyzer...")
        analyzer = AWSSecurityAnalyzer(
            profile_name=args.profile,
            regions=args.regions
        )

        # Print start message
        print(f"Starting security assessment for account {analyzer.account_id}")
        print(f"Analyzing regions: {', '.join(args.regions)}")

        if args.verbose:
            print("Running in verbose mode - detailed logs will be shown")

        # Run assessment
        logger.info("Starting comprehensive security assessment...")
        results = analyzer.run_full_assessment()

        # Print summary to console
        print_assessment_summary(results)

        # Export detailed results
        filename = analyzer.export_findings(
            format_type=args.output,
            filename=args.filename
        )
        print(f"\nDetailed results exported to: {filename}")

        # Print recommendations
        print_recommendations(results)

        print("\n" + "="*60)
        print("Assessment completed successfully!")

        # Return exit code based on risk level
        risk_level = results.get('summary', {}).get('risk_level', 'UNKNOWN')
        if risk_level in ['CRITICAL', 'HIGH']:
            return 2  # High risk exit code
        elif risk_level == 'MEDIUM':
            return 1  # Medium risk exit code
        else:
            return 0  # Low risk or success

    except KeyboardInterrupt:
        print("\n\nAssessment interrupted by user")
        return 130

    except Exception as e:
        logger.error(f"Assessment failed: {e}")

        if args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print(f"\nError: {e}")
            print("Use --verbose for detailed error information")

        return 1


if __name__ == "__main__":
    sys.exit(main())