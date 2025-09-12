"""
Directory and File Permissions section checker for YugabyteDB CIS Benchmark
"""

import logging
import os

from core.base_checker import BaseChecker
from core.models import CISControl, ControlResult


class DirectoryPermissionsChecker(BaseChecker):
    """Checker for Directory and File Permissions section controls"""

    def check_control(self, control: CISControl) -> ControlResult:
        """Route control check to appropriate method"""
        control_id = control.control_id

        try:
            if control_id.startswith("2.1"):
                return self._check_data_directory_permissions(control)
            elif control_id.startswith("2.2"):
                return self._check_log_file_permissions(control)
            elif control_id.startswith("2.3"):
                return self._check_config_file_permissions(control)
            elif control_id.startswith("2.4"):
                return self._check_backup_directory_permissions(control)
            else:
                return self._check_generic_directory_permissions(control)
        except Exception as e:
            return self._create_fail_result(control, f"Error during directory permissions check: {str(e)}")

    def _check_data_directory_permissions(self, control: CISControl) -> ControlResult:
        """Check data directory permissions"""
        try:
            data_dir = self.db.get_setting('data_directory')
            if not data_dir:
                return self._create_fail_result(control, "Could not determine data directory location")

            # Since this requires OS-level access, we provide the directory path for manual verification
            return self._create_info_result(control,
                                            f"Data directory: {data_dir}. Manual verification required for permissions (should be 0700).",
                                            expected="Directory permissions: 0700 (owner only)",
                                            actual=f"Directory path: {data_dir}")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking data directory permissions: {str(e)}")

    def _check_log_file_permissions(self, control: CISControl) -> ControlResult:
        """Check log file permissions"""
        try:
            log_destination = self.db.get_setting('log_destination')
            log_directory = self.db.get_setting('log_directory') or "Unknown"
            log_filename = self.db.get_setting('log_filename') or "Unknown"

            if not log_destination:
                return self._create_fail_result(control, "Could not determine log destination")

            log_info = f"Log destination: {log_destination}, Directory: {log_directory}, Filename pattern: {log_filename}"

            return self._create_info_result(control,
                                            f"{log_info}. Manual verification required for log file permissions (should be 0640).",
                                            expected="Log file permissions: 0640",
                                            actual=log_info)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking log file permissions: {str(e)}")

    def _check_config_file_permissions(self, control: CISControl) -> ControlResult:
        """Check configuration file permissions"""
        try:
            config_file = self.db.get_setting('config_file')
            if not config_file:
                return self._create_fail_result(control, "Could not determine configuration file location")

            return self._create_info_result(control,
                                            f"Configuration file: {config_file}. Manual verification required for permissions (should be 0600).",
                                            expected="Config file permissions: 0600 (owner read/write only)",
                                            actual=f"Config file path: {config_file}")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking config file permissions: {str(e)}")

    def _check_backup_directory_permissions(self, control: CISControl) -> ControlResult:
        """Check backup directory permissions"""
        try:
            # YugabyteDB backup directories are typically configured separately
            # This would require checking yugabytedb-tools configuration

            return self._create_skip_result(control,
                                            "Backup directory permissions require manual verification of yugabytedb-tools configuration")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking backup directory permissions: {str(e)}")

    def _check_generic_directory_permissions(self, control: CISControl) -> ControlResult:
        """Generic directory permissions check"""
        try:
            # Check if audit command contains file/directory references
            audit_cmd = control.audit.lower()

            if 'data_directory' in audit_cmd:
                return self._check_data_directory_permissions(control)
            elif 'log' in audit_cmd:
                return self._check_log_file_permissions(control)
            elif 'config' in audit_cmd:
                return self._check_config_file_permissions(control)
            else:
                return self._create_skip_result(control,
                                                "Generic directory permissions check - manual OS-level verification required")

        except Exception as e:
            return self._create_fail_result(control, f"Error in generic directory permissions check: {str(e)}")
