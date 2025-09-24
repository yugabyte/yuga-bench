"""
Installation and Patches section checker for YugabyteDB CIS Benchmark
"""

import logging

from core.base_checker import BaseChecker
from core.models import CISControl, ControlResult


class InstallationPatchesChecker(BaseChecker):
    """Checker for Installation and Patches section controls"""

    def check_control(self, control: CISControl) -> ControlResult:
        """Route control check to appropriate method"""
        control_id = control.control_id

        try:
            if control_id.startswith("1.1"):
                return self._check_packages_from_authorized_repo(control)
            elif control_id.startswith("1.2"):
                return self._check_systemd_service_enabled(control)
            elif control_id.startswith("1.3"):
                return self._check_cluster_initialized(control)
            else:
                return self._check_generic_installation(control)
        except Exception as e:
            return self._create_fail_result(control, f"Error during installation check: {str(e)}")

    def _check_installation_version(self, control: CISControl) -> ControlResult:
        """Check YugabyteDB installation and version"""
        try:
            version_info = self.db.execute_query("SELECT version();")
            if not version_info:
                return self._create_fail_result(control, "Could not retrieve version information")

            version_string = version_info[0]['version']

            # Check if it's YugabyteDB
            if 'yugabyte' not in version_string.lower():
                return self._create_fail_result(control, "Not running YugabyteDB",
                                                expected="YugabyteDB", actual=version_string)

            # Extract version number if possible
            import re
            version_match = re.search(r'(\d+\.\d+\.\d+)', version_string)
            version_number = version_match.group(1) if version_match else "Unknown"

            return self._create_pass_result(control,
                                            f"YugabyteDB version {version_number} detected",
                                            expected="YugabyteDB installation",
                                            actual=f"YugabyteDB {version_number}")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking installation: {str(e)}")

    def _check_patches_updates(self, control: CISControl) -> ControlResult:
        """Check for patches and updates status"""
        try:
            # Get version information
            version_info = self.db.execute_query("SELECT version();")
            if not version_info:
                return self._create_fail_result(control, "Could not retrieve version information for patch check")

            version_string = version_info[0]['version']

            # This would typically require checking against known CVEs or update databases
            # For now, we'll provide informational status
            return self._create_info_result(control,
                                            f"Current version: {version_string}. Manual verification required for latest patches.",
                                            actual=version_string)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking patches: {str(e)}")

    def _check_cluster_initialized(self, control: CISControl) -> ControlResult:
        """Check data cluster initialized successfully"""
        return self._create_skip_result(control, "TODO - Implementation pending")

    def _check_packages_from_authorized_repo(self, control: CISControl) -> ControlResult:
        """Check packages are obtained from authorized repository"""
        return self._create_skip_result(control, "Manual - TODO - Implementation pending")

    def _check_systemd_service_enabled(self, control: CISControl) -> ControlResult:
        """Check systemd service files enabled"""
        return self._create_skip_result(control, "Manual - TODO - Implementation pending")

    def _check_installation_integrity(self, control: CISControl) -> ControlResult:
        """Check installation integrity"""
        try:
            # Check if basic system tables exist
            system_tables = [
                'pg_class', 'pg_database', 'pg_user', 'pg_settings'
            ]

            missing_tables = []
            for table in system_tables:
                if not self.db.check_table_exists(table, 'pg_catalog'):
                    missing_tables.append(table)

            if missing_tables:
                return self._create_fail_result(control,
                                                f"Missing system tables: {', '.join(missing_tables)}",
                                                expected="All system tables present",
                                                actual=f"Missing: {', '.join(missing_tables)}")

            # Check if we can access basic system information
            basic_checks = [
                "SELECT current_database();",
                "SELECT current_user;",
                "SELECT count(*) FROM pg_settings;"
            ]

            for check_query in basic_checks:
                result = self.db.execute_query(check_query)
                if not result:
                    return self._create_fail_result(control,
                                                    f"Failed basic system check: {check_query}")

            return self._create_pass_result(control,
                                            "Installation integrity checks passed",
                                            expected="All system components accessible",
                                            actual="All basic checks passed")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking installation integrity: {str(e)}")

    def _check_generic_installation(self, control: CISControl) -> ControlResult:
        """Generic installation check"""
        # Try to extract setting name from audit command
        setting_name = self._extract_setting_name_from_audit(control.audit)

        if setting_name:
            setting_value = self.db.get_setting(setting_name)
            return self._create_info_result(control,
                                            f"Installation setting {setting_name}: {setting_value}",
                                            actual=setting_value)
        else:
            return self._create_skip_result(control, "Generic installation check - manual verification required")
