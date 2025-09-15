"""
Security Services Analyzer

Handles AWS security services analysis (GuardDuty, Config, CloudTrail, etc.)
"""

import logging
from typing import Any, Dict, List

import boto3

logger = logging.getLogger(__name__)


class SecurityServicesAnalyzer:
    """Handles AWS security services analysis"""

    def __init__(self, session: boto3.Session, regions: List[str]):
        self.session = session
        self.regions = regions

    def analyze_security_services(self) -> Dict[str, Any]:
        """Analyze AWS security services configuration"""
        logger.info("Analyzing security services...")

        findings = {
            'guardduty_status': {},
            'config_status': {},
            'cloudtrail_status': {},
            'security_hub_status': {}
        }

        for region in self.regions:
            try:
                logger.info(f"Analyzing security services in region: {region}")
                self._analyze_region_services(region, findings)
            except Exception as e:
                logger.error(f"Security services analysis failed for region {region}: {e}")

        # Analyze CloudTrail globally
        if self.regions:
            self._analyze_cloudtrail_global(findings)

        return findings

    def _analyze_region_services(self, region: str, findings: Dict[str, Any]) -> None:
        """Analyze security services for a specific region"""
        self._check_guardduty(region, findings)
        self._check_config(region, findings)

    def _check_guardduty(self, region: str, findings: Dict[str, Any]) -> None:
        """Check GuardDuty status"""
        try:
            guardduty = self.session.client('guardduty', region_name=region)
            detectors = guardduty.list_detectors()['DetectorIds']

            if detectors:
                detector_details = guardduty.get_detector(DetectorId=detectors[0])
                findings['guardduty_status'][region] = {
                    'enabled': detector_details['Status'] == 'ENABLED',
                    'finding_frequency': detector_details.get('FindingPublishingFrequency', 'UNKNOWN')
                }
                logger.info(f"GuardDuty in {region}: {detector_details['Status']}")
            else:
                findings['guardduty_status'][region] = {'enabled': False}
                logger.warning(f"GuardDuty not enabled in {region}")

        except Exception as e:
            logger.error(f"GuardDuty check failed in {region}: {e}")
            findings['guardduty_status'][region] = {'enabled': False, 'error': True}

    def _check_config(self, region: str, findings: Dict[str, Any]) -> None:
        """Check AWS Config status"""
        try:
            config = self.session.client('config', region_name=region)
            config_recorders = config.describe_configuration_recorders()['ConfigurationRecorders']

            findings['config_status'][region] = {
                'enabled': len(config_recorders) > 0,
                'recorder_count': len(config_recorders)
            }

            logger.info(f"AWS Config in {region}: {len(config_recorders)} recorders")

        except Exception as e:
            logger.error(f"AWS Config check failed in {region}: {e}")
            findings['config_status'][region] = {'enabled': False, 'error': True}

    def _analyze_cloudtrail_global(self, findings: Dict[str, Any]) -> None:
        """Analyze CloudTrail configuration globally"""
        try:
            cloudtrail = self.session.client('cloudtrail', region_name=self.regions[0])
            trails = cloudtrail.describe_trails()['trailList']
            global_trails = [t for t in trails if t.get('IsMultiRegionTrail', False)]

            findings['cloudtrail_status'] = {
                'global_trails': len(global_trails),
                'total_trails': len(trails),
                'has_global_logging': len(global_trails) > 0
            }

            logger.info(f"CloudTrail: {len(trails)} total trails, {len(global_trails)} global trails")

        except Exception as e:
            logger.error(f"CloudTrail analysis failed: {e}")
            findings['cloudtrail_status'] = {'enabled': False, 'error': True}