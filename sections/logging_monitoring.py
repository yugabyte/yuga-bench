"""
Logging Monitoring and Auditing section checker for YugabyteDB CIS Benchmark
"""

import logging

from core.base_checker import BaseChecker
from core.models import CISControl, ControlResult


class LoggingMonitoringChecker(BaseChecker):
    """Checker for Logging Monitoring and Auditing section controls"""

    def check_control(self, control: CISControl) -> ControlResult:
        """Route control check to appropriate method"""
        control_id = control.control_id

        try:
            if control_id == "3.1.1":
                return self._check_logging_rationale(control)
            elif control_id == "3.1.2":
                return self._check_log_destination(control)
            elif control_id == "3.1.3":
                return self._check_log_filename_pattern(control)
            elif control_id == "3.1.4":
                return self._check_log_file_permissions(control)
            elif control_id == "3.1.5":
                return self._check_log_truncate_on_rotation(control)
            elif control_id == "3.1.6":
                return self._check_log_file_lifetime(control)
            elif control_id == "3.1.7":
                return self._check_max_log_file_size(control)
            elif control_id == "3.1.8":
                return self._check_log_file_facility(control)
            elif control_id == "3.1.9":
                return self._check_syslog_messages_not_suppressed(control)
            elif control_id == "3.1.10":
                return self._check_log_messages_not_lost_due_to_size(control)
            elif control_id.startswith("3.2"):
                return self._check_statement_logging(control)
            elif control_id.startswith("3.3"):
                return self._check_connection_logging(control)
            else:
                return self._check_generic_logging_setting(control)
        except Exception as e:
            return self._create_fail_result(control, f"Error during logging check: {str(e)}")

    def _check_logging_rationale(self, control: CISControl) -> ControlResult:
        """Check logging monitoring and auditing rationale"""
        return self._create_skip_result(control, "Logging monitoring and auditing rationale - manual verification required")

    def _check_log_destination(self, control: CISControl) -> ControlResult:
        """Check log_destination setting"""
        expected_values = ['stderr', 'csvlog', 'syslog']
        return self._check_setting_value(control, expected_values, 'log_destination')

    def _check_log_filename_pattern(self, control: CISControl) -> ControlResult:
        """Check log filename pattern for time-based rotation"""
        current_value = self.db.get_setting('log_filename')
        if not current_value:
            return self._create_fail_result(control, "Could not retrieve log_filename setting")

        # Check if pattern includes time-based components for rotation
        time_patterns = ['%Y', '%m', '%d', '%H', '%M', '%S', '%a']
        has_time_pattern = any(pattern in current_value for pattern in time_patterns)

        if has_time_pattern:
            return self._create_pass_result(control,
                                            f"Log filename pattern includes time-based rotation: {current_value}",
                                            expected="Time-based rotation pattern",
                                            actual=current_value)
        else:
            return self._create_fail_result(control,
                                            f"Log filename pattern lacks time-based rotation: {current_value}",
                                            expected="Time-based rotation pattern",
                                            actual=current_value)

    def _check_log_file_permissions(self, control: CISControl) -> ControlResult:
        """Check log file permissions"""
        return self._create_skip_result(control, "Log file permissions check requires manual OS-level verification")

    def _check_log_truncate_on_rotation(self, control: CISControl) -> ControlResult:
        """Check log truncate on rotation setting"""
        return self._check_boolean_setting(control, True, 'log_truncate_on_rotation')

    def _check_log_file_lifetime(self, control: CISControl) -> ControlResult:
        """Check log file lifetime settings"""
        setting_name = 'log_rotation_age'
        setting_value = self.db.get_setting(setting_name)

        if not setting_value:
            return self._create_fail_result(control, f"Could not retrieve {setting_name} setting")

        # Check if rotation age is configured (not 0)
        if setting_value == '0' or setting_value == 0:
            return self._create_warn_result(control,
                                            f"Log rotation age is disabled: {setting_value}",
                                            expected="Non-zero rotation age",
                                            actual=str(setting_value))
        else:
            return self._create_pass_result(control,
                                            f"Log rotation age is configured: {setting_value}",
                                            expected="Non-zero rotation age",
                                            actual=str(setting_value))

    def _check_max_log_file_size(self, control: CISControl) -> ControlResult:
        """Check maximum log file size"""
        setting_name = 'log_rotation_size'
        setting_value = self.db.get_setting(setting_name)

        if not setting_value:
            return self._create_fail_result(control, f"Could not retrieve {setting_name} setting")

        # Check if rotation size is configured (not 0)
        if setting_value == '0' or setting_value == 0:
            return self._create_warn_result(control,
                                            f"Log rotation size is disabled: {setting_value}",
                                            expected="Non-zero rotation size",
                                            actual=str(setting_value))
        else:
            return self._create_pass_result(control,
                                            f"Log rotation size is configured: {setting_value}",
                                            expected="Non-zero rotation size",
                                            actual=str(setting_value))

    def _check_log_file_facility(self, control: CISControl) -> ControlResult:
        """Check syslog facility setting"""
        return self._check_setting_value(control, ['local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'], 'syslog_facility')

    def _check_syslog_messages_not_suppressed(self, control: CISControl) -> ControlResult:
        """Check that syslog messages are not suppressed"""
        silent_mode = self.db.get_setting('silent_mode')

        if silent_mode == 'on':
            return self._create_fail_result(control,
                                            "Silent mode is enabled, syslog messages may be suppressed",
                                            expected="silent_mode = off",
                                            actual="silent_mode = on")
        else:
            return self._create_pass_result(control,
                                            "Silent mode is disabled, syslog messages not suppressed",
                                            expected="silent_mode = off",
                                            actual=f"silent_mode = {silent_mode}")

    def _check_log_messages_not_lost_due_to_size(self, control: CISControl) -> ControlResult:
        """Check that log messages are not lost due to size constraints"""
        # Check if log rotation is properly configured
        rotation_age = self.db.get_setting('log_rotation_age')
        rotation_size = self.db.get_setting('log_rotation_size')

        issues = []
        if not rotation_age or rotation_age == '0':
            issues.append("log_rotation_age is not configured")
        if not rotation_size or rotation_size == '0':
            issues.append("log_rotation_size is not configured")

        if issues:
            return self._create_warn_result(control,
                                            f"Log rotation may not prevent message loss: {', '.join(issues)}",
                                            expected="Both rotation age and size configured",
                                            actual=f"age={rotation_age}, size={rotation_size}")
        else:
            return self._create_pass_result(control,
                                            f"Log rotation configured to prevent message loss: age={rotation_age}, size={rotation_size}",
                                            expected="Both rotation age and size configured",
                                            actual=f"age={rotation_age}, size={rotation_size}")

    def _check_statement_logging(self, control: CISControl) -> ControlResult:
        """Check statement logging configuration"""
        control_id = control.control_id

        if "log_statement" in control.audit.lower():
            return self._check_setting_value(control, ['all', 'ddl', 'mod'], 'log_statement')
        elif "log_min_duration_statement" in control.audit.lower():
            setting_value = self.db.get_setting('log_min_duration_statement')
            if setting_value == '-1':
                return self._create_warn_result(control,
                                                "Statement duration logging is disabled",
                                                expected="Non-negative value (ms)",
                                                actual="-1 (disabled)")
            else:
                return self._create_pass_result(control,
                                                f"Statement duration logging configured: {setting_value}ms",
                                                expected="Non-negative value (ms)",
                                                actual=f"{setting_value}ms")
        else:
            return self._check_generic_logging_setting(control)

    def _check_connection_logging(self, control: CISControl) -> ControlResult:
        """Check connection logging configuration"""
        if "log_connections" in control.audit.lower():
            return self._check_boolean_setting(control, True, 'log_connections')
        elif "log_disconnections" in control.audit.lower():
            return self._check_boolean_setting(control, True, 'log_disconnections')
        elif "log_truncate_on_rotation" in control.audit.lower():
            return self._check_boolean_setting(control, True, 'log_truncate_on_rotation')
        elif "log_line_prefix" in control.audit.lower():
            return self._check_log_line_prefix(control)
        else:
            return self._check_generic_logging_setting(control)

    def _check_log_line_prefix(self, control: CISControl) -> ControlResult:
        """Check log line prefix configuration"""
        setting_value = self.db.get_setting('log_line_prefix')
        required_components = ['%t', '%u', '%d', '%p']

        if not setting_value:
            return self._create_fail_result(control, "log_line_prefix is not configured")

        missing_components = [comp for comp in required_components if comp not in setting_value]

        if not missing_components:
            return self._create_pass_result(control,
                                            f"log_line_prefix includes all required components: {setting_value}",
                                            expected="Include %t, %u, %d, %p",
                                            actual=setting_value)
        else:
            return self._create_fail_result(control,
                                            f"log_line_prefix missing components {missing_components}: {setting_value}",
                                            expected="Include %t, %u, %d, %p",
                                            actual=setting_value)

    def _check_generic_logging_setting(self, control: CISControl) -> ControlResult:
        """Generic logging setting check"""
        # Extract setting name from audit command
        setting_name = self._extract_setting_name_from_audit(control.audit)

        if setting_name:
            setting_value = self.db.get_setting(setting_name)
            return self._create_info_result(control,
                                            f"Logging setting {setting_name}: {setting_value}",
                                            actual=str(setting_value))
        else:
            return self._create_skip_result(control, "Generic logging check - manual verification required")
