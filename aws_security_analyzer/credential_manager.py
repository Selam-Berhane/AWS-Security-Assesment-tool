"""
IAM Credential Report Manager

Handles credential report generation, caching, and parsing
"""

import csv
import io
import logging
import time
from typing import Dict, List, Optional

import boto3

logger = logging.getLogger(__name__)


class CredentialReportManager:
    """Manages IAM credential report operations"""

    def __init__(self, session: boto3.Session):
        self.session = session
        self._cached_report = None
        self._cache_timestamp = None
        self._cache_duration = 300  # 5 minutes

    def get_credential_report(self) -> Optional[List[Dict[str, str]]]:
        """Get IAM credential report data with caching"""
        current_time = time.time()

        # Return cached report if still valid
        if (self._cached_report and self._cache_timestamp and
            current_time - self._cache_timestamp < self._cache_duration):
            logger.debug("Using cached credential report")
            return self._cached_report

        try:
            iam = self.session.client('iam')

            # Generate credential report
            try:
                iam.generate_credential_report()

                # Wait for report generation
                for _ in range(10):  # Wait up to 10 seconds
                    try:
                        response = iam.get_credential_report()
                        break
                    except iam.exceptions.CredentialReportNotReadyException:
                        time.sleep(1)
                else:
                    raise Exception("Credential report generation timeout")

            except iam.exceptions.CredentialReportNotPresentException:
                iam.generate_credential_report()
                time.sleep(2)
                response = iam.get_credential_report()

            # Parse CSV data
            credential_data = response['Content'].decode('utf-8')
            csv_reader = csv.DictReader(io.StringIO(credential_data))

            # Cache the result
            self._cached_report = list(csv_reader)
            self._cache_timestamp = current_time

            logger.info(f"Retrieved credential report with {len(self._cached_report)} entries")
            return self._cached_report

        except Exception as e:
            logger.error(f"Failed to get credential report: {e}")
            return None

    def invalidate_cache(self) -> None:
        """Invalidate the cached credential report"""
        self._cached_report = None
        self._cache_timestamp = None
        logger.debug("Credential report cache invalidated")