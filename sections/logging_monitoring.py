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
            elif control_id == "3.1.11":
                return self._check_program_name_syslog_message(control)
            elif control_id == "3.1.12":
                return self._check_correct_message_server_log(control)
            elif control_id == "3.1.13":
                return self._check_ysql_statement_error_recorded(control)
            elif control_id == "3.1.14":
                return self._check_debug_print_parse_disabled(control)
            elif control_id == "3.1.15":
                return self._check_debug_print_rewritten_disabled(control)
            elif control_id == "3.1.16":
                return self._check_debug_print_plan_disabled(control)
            elif control_id == "3.1.17":
                return self._check_debug_pretty_print_enabled(control)
            elif control_id == "3.1.18":
                return self._check_log_connections_enabled(control)
            elif control_id == "3.1.19":
                return self._check_log_disconnections_enabled(control)
            elif control_id == "3.1.20":
                return self._check_log_error_verbosity(control)
            elif control_id == "3.1.21":
                return self._check_log_hostname(control)
            elif control_id == "3.1.22":
                return self._check_log_line_prefix(control)
            elif control_id == "3.1.23":
                return self._check_log_statement(control)
            elif control_id == "3.1.24":
                return self._check_log_timezone(control)
            elif control_id.startswith("3.2"):
                return self._check_audit_extension_enabled(control)
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
        """Check log file permissions using log_file_mode setting"""
        try:
            log_file_mode = self.db.get_setting('log_file_mode')

            if not log_file_mode:
                return self._create_fail_result(control, 
                                              "Could not retrieve log_file_mode setting",
                                              expected="0600",
                                              actual="NULL")

            # Expected secure permission is 0600 (owner read/write only)
            expected_mode = "0600"

            if log_file_mode == expected_mode:
                return self._create_pass_result(control, 
                                              f"Log file permissions are correctly set: {log_file_mode}",
                                              expected=expected_mode,
                                              actual=log_file_mode)
            else:
                # Check if it's a more restrictive setting (0400 - read only)
                if log_file_mode == "0400":
                    return self._create_pass_result(control, 
                                                  f"Log file permissions are restrictive (read-only): {log_file_mode}",
                                                  expected=expected_mode,
                                                  actual=log_file_mode)

                # Check for potentially insecure permissions
                insecure_modes = ["0644", "0666", "0755", "0777"]
                if log_file_mode in insecure_modes:
                    return self._create_fail_result(control, 
                                                  f"Log file permissions are too permissive: {log_file_mode}",
                                                  expected=expected_mode,
                                                  actual=log_file_mode)
                else:
                    return self._create_warn_result(control, 
                                                  f"Log file permissions set to non-standard value: {log_file_mode}",
                                                  expected=expected_mode,
                                                  actual=log_file_mode)
                                                  
        except Exception as e:
            return self._create_fail_result(control, f"Error checking log file permissions: {str(e)}")

    def _check_log_truncate_on_rotation(self, control: CISControl) -> ControlResult:
        """Check log truncate on rotation setting"""
        setting_name = 'log_truncate_on_rotation'
        setting_value = self.db.get_setting(setting_name)

        if not setting_value:
            return self._create_fail_result(control, f"Could not retrieve {setting_name} setting")

        if setting_value == 'off':
            return self._create_fail_result(control,
                                            f"Log truncate on rotation is disabled: {setting_value}",
                                            expected="on",
                                            actual=str(setting_value))
        else:
            return self._create_pass_result(control,
                                            f"Log truncate on rotation is configured: {setting_value}",
                                            expected="on",
                                            actual=str(setting_value))

    def _check_log_file_lifetime(self, control: CISControl) -> ControlResult:
        """Check log file lifetime settings"""
        setting_name = 'log_rotation_age'
        setting_value = self.db.get_setting(setting_name)

        if not setting_value:
            return self._create_fail_result(control, f"Could not retrieve {setting_name} setting")

        # Check if rotation age is configured (not 0)
        if setting_value == '0' or setting_value == 0:
            return self._create_fail_result(control,
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
            return self._create_fail_result(control,
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
        """Check that syslog sequence numbers are enabled to prevent message suppression"""
        try:
            syslog_sequence_numbers = self.db.get_setting('syslog_sequence_numbers')

            if not syslog_sequence_numbers:
                return self._create_fail_result(control, 
                                            "Could not retrieve syslog_sequence_numbers setting",
                                            expected="on",
                                            actual="NULL")

            if syslog_sequence_numbers.lower() == 'on':
                return self._create_pass_result(control, 
                                            "Syslog sequence numbers are enabled - messages will not be suppressed",
                                            expected="on",
                                            actual=syslog_sequence_numbers)
            else:
                return self._create_fail_result(control, 
                                            f"Syslog sequence numbers are disabled - messages may be suppressed: {syslog_sequence_numbers}",
                                            expected="on",
                                            actual=syslog_sequence_numbers)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking syslog_sequence_numbers: {str(e)}")

    def _check_log_messages_not_lost_due_to_size(self, control: CISControl) -> ControlResult:
        """Check that long log messages are split when logging to syslog to prevent message loss"""
        try:
            syslog_split_messages = self.db.get_setting('syslog_split_messages')

            if not syslog_split_messages:
                return self._create_fail_result(control, 
                                            "Could not retrieve syslog_split_messages setting",
                                            expected="on",
                                            actual="NULL")

            if syslog_split_messages.lower() == 'on':
                return self._create_pass_result(control, 
                                            "Syslog message splitting is enabled - long messages will not be lost",
                                            expected="on",
                                            actual=syslog_split_messages)
            else:
                return self._create_fail_result(control, 
                                            f"Syslog message splitting is disabled - long messages may be truncated: {syslog_split_messages}",
                                            expected="on",
                                            actual=syslog_split_messages)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking syslog_split_messages: {str(e)}")

    def _check_statement_logging(self, control: CISControl) -> ControlResult:
        """Check statement logging configuration"""
        control_id = control.control_id

        if "log_statement" in control.audit.lower():
            return self._check_setting_value(control, ['all', 'ddl', 'mod'], 'log_statement')
        elif "log_min_duration_statement" in control.audit.lower():
            setting_value = self.db.get_setting('log_min_duration_statement')
            if setting_value == '-1':
                return self._create_fail_result(control,
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
        """Check log_line_prefix configuration includes required components"""
        try:
            log_line_prefix = self.db.get_setting('log_line_prefix')

            if not log_line_prefix:
                return self._create_fail_result(control, 
                                            "Could not retrieve log_line_prefix setting",
                                            expected="%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h",
                                            actual="NULL")

            # Define minimum required components
            required_components = {
                '%m': 'timestamp with milliseconds',
                '%p': 'process ID',
                '%l': 'session line number',
                '%d': 'database name',
                '%u': 'user name',
                '%a': 'application name',
                '%h': 'remote host'
            }

            # Check which required components are present
            missing_components = []
            present_components = []

            for component, description in required_components.items():
                if component in log_line_prefix:
                    present_components.append(f"{component} ({description})")
                else:
                    missing_components.append(f"{component} ({description})")

            if missing_components:
                return self._create_fail_result(control, 
                                            f"log_line_prefix missing required components: {', '.join(missing_components)}",
                                            expected="%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h (minimum)",
                                            actual=log_line_prefix)
            else:
                return self._create_pass_result(control, 
                                            f"log_line_prefix includes all required components: {', '.join(present_components)}",
                                            expected="Includes %m, %p, %l, %d, %u, %a, %h",
                                            actual=log_line_prefix)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking log_line_prefix: {str(e)}")

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

    def _check_program_name_syslog_message(self, control: CISControl) -> ControlResult:
        """Check syslog program name/identifier setting"""
        try:
            syslog_ident = self.db.get_setting('syslog_ident')

            if not syslog_ident:
                return self._create_fail_result(control, 
                                              "Could not retrieve syslog_ident setting",
                                              expected="Descriptive identifier (e.g., yugabyte, postgres)",
                                              actual="NULL")

            acceptable_identifiers = ['yugabyte', 'postgres', 'postgresql', 'ybdb']

            if syslog_ident.lower() in [ident.lower() for ident in acceptable_identifiers]:
                return self._create_pass_result(control, 
                                              f"Syslog identifier is properly set: {syslog_ident}",
                                              expected="Descriptive database identifier",
                                              actual=syslog_ident)

            problematic_identifiers = ['', 'app', 'service', 'daemon', 'server', 'db', 'test']

            if syslog_ident.lower() in problematic_identifiers:
                return self._create_fail_result(control, 
                                              f"Syslog identifier is too generic or unclear: {syslog_ident}",
                                              expected="Descriptive database identifier",
                                              actual=syslog_ident)

            sensitive_patterns = ['prod', 'dev', 'test', 'staging', 'v1', 'v2', 'server', 'host']
            has_sensitive = any(pattern in syslog_ident.lower() for pattern in sensitive_patterns)

            if has_sensitive:
                return self._create_warn_result(control, 
                                              f"Syslog identifier may contain environment/version info: {syslog_ident}",
                                              expected="Generic database identifier without environment details",
                                              actual=syslog_ident)

            if len(syslog_ident) >= 3 and syslog_ident.replace('-', '').replace('_', '').isalnum():
                return self._create_pass_result(control, 
                                              f"Custom syslog identifier appears appropriate: {syslog_ident}",
                                              expected="Descriptive database identifier",
                                              actual=syslog_ident)

            return self._create_warn_result(control, 
                                          f"Syslog identifier format should be reviewed: {syslog_ident}",
                                          expected="Alphanumeric identifier (3+ characters)",
                                          actual=syslog_ident)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking syslog identifier: {str(e)}")

    def _check_correct_message_server_log(self, control: CISControl) -> ControlResult:
        """Check log_min_messages setting"""
        try:
            log_min_messages = self.db.get_setting('log_min_messages')

            if not log_min_messages:
                return self._create_fail_result(control, 
                                            "Could not retrieve log_min_messages setting",
                                            expected="warning",
                                            actual="NULL")

            if log_min_messages.lower() == 'warning':
                return self._create_pass_result(control, 
                                            f"Log minimum messages correctly set: {log_min_messages}",
                                            expected="warning",
                                            actual=log_min_messages)
            else:
                return self._create_fail_result(control, 
                                            f"Log minimum messages not set to recommended level: {log_min_messages}",
                                            expected="warning",
                                            actual=log_min_messages)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking log_min_messages: {str(e)}")

    def _check_ysql_statement_error_recorded(self, control: CISControl) -> ControlResult:
        """Check log_min_error_statement setting"""
        try:
            log_min_error_statement = self.db.get_setting('log_min_error_statement')

            if not log_min_error_statement:
                return self._create_fail_result(control, 
                                            "Could not retrieve log_min_error_statement setting",
                                            expected="error",
                                            actual="NULL")

            acceptable_levels = ['error', 'fatal', 'panic']

            if log_min_error_statement.lower() in acceptable_levels:
                return self._create_pass_result(control, 
                                            f"Error statement logging properly configured: {log_min_error_statement}",
                                            expected="error or higher",
                                            actual=log_min_error_statement)
            else:
                return self._create_fail_result(control, 
                                            f"Error statement logging not configured to at least ERROR: {log_min_error_statement}",
                                            expected="error",
                                            actual=log_min_error_statement)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking log_min_error_statement: {str(e)}")

    def _check_debug_print_parse_disabled(self, control: CISControl) -> ControlResult:
        """Check debug_print_parse setting is disabled"""
        try:
            debug_print_parse = self.db.get_setting('debug_print_parse')

            if not debug_print_parse:
                return self._create_fail_result(control, 
                                            "Could not retrieve debug_print_parse setting",
                                            expected="off",
                                            actual="NULL")

            if debug_print_parse.lower() == 'off':
                return self._create_pass_result(control, 
                                            "Debug print parse correctly disabled",
                                            expected="off",
                                            actual=debug_print_parse)
            else:
                return self._create_fail_result(control, 
                                            f"Debug print parse is enabled - security risk: {debug_print_parse}",
                                            expected="off",
                                            actual=debug_print_parse)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking debug_print_parse: {str(e)}")

    def _check_debug_print_rewritten_disabled(self, control: CISControl) -> ControlResult:
        """Check debug_print_rewritten setting is disabled"""
        try:
            debug_print_rewritten = self.db.get_setting('debug_print_rewritten')

            if not debug_print_rewritten:
                return self._create_fail_result(control, 
                                            "Could not retrieve debug_print_rewritten setting",
                                            expected="off",
                                            actual="NULL")

            if debug_print_rewritten.lower() == 'off':
                return self._create_pass_result(control, 
                                            "Debug print rewritten correctly disabled",
                                            expected="off",
                                            actual=debug_print_rewritten)
            else:
                return self._create_fail_result(control, 
                                            f"Debug print rewritten is enabled - security risk: {debug_print_rewritten}",
                                            expected="off",
                                            actual=debug_print_rewritten)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking debug_print_rewritten: {str(e)}")

    def _check_debug_print_plan_disabled(self, control: CISControl) -> ControlResult:
        """Check debug_print_plan setting is disabled"""
        try:
            debug_print_plan = self.db.get_setting('debug_print_plan')

            if not debug_print_plan:
                return self._create_fail_result(control, 
                                            "Could not retrieve debug_print_plan setting",
                                            expected="off",
                                            actual="NULL")

            if debug_print_plan.lower() == 'off':
                return self._create_pass_result(control, 
                                            "Debug print plan correctly disabled",
                                            expected="off",
                                            actual=debug_print_plan)
            else:
                return self._create_fail_result(control, 
                                            f"Debug print plan is enabled - security risk: {debug_print_plan}",
                                            expected="off",
                                            actual=debug_print_plan)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking debug_print_plan: {str(e)}")

    def _check_debug_pretty_print_enabled(self, control: CISControl) -> ControlResult:
        """Check debug_pretty_print setting is enabled"""
        try:
            debug_pretty_print = self.db.get_setting('debug_pretty_print')

            if not debug_pretty_print:
                return self._create_fail_result(control, 
                                            "Could not retrieve debug_pretty_print setting",
                                            expected="on",
                                            actual="NULL")

            if debug_pretty_print.lower() == 'on':
                return self._create_pass_result(control, 
                                            "Debug pretty print correctly enabled",
                                            expected="on",
                                            actual=debug_pretty_print)
            else:
                return self._create_fail_result(control, 
                                            f"Debug pretty print is not enabled: {debug_pretty_print}",
                                            expected="on",
                                            actual=debug_pretty_print)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking debug_pretty_print: {str(e)}")

    def _check_log_connections_enabled(self, control: CISControl) -> ControlResult:
        """Check log_connections setting is enabled"""
        try:
            log_connections = self.db.get_setting('log_connections')

            if not log_connections:
                return self._create_fail_result(control, 
                                            "Could not retrieve log_connections setting",
                                            expected="on",
                                            actual="NULL")

            if log_connections.lower() == 'on':
                return self._create_pass_result(control, 
                                            "Connection logging is properly enabled",
                                            expected="on",
                                            actual=log_connections)
            else:
                return self._create_fail_result(control, 
                                            f"Connection logging is not enabled: {log_connections}",
                                            expected="on",
                                            actual=log_connections)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking log_connections: {str(e)}")

    def _check_log_disconnections_enabled(self, control: CISControl) -> ControlResult:
        """Check log_disconnections setting is enabled"""
        try:
            log_disconnections = self.db.get_setting('log_disconnections')

            if not log_disconnections:
                return self._create_fail_result(control, 
                                            "Could not retrieve log_disconnections setting",
                                            expected="on",
                                            actual="NULL")

            if log_disconnections.lower() == 'on':
                return self._create_pass_result(control, 
                                            "Disconnection logging is properly enabled",
                                            expected="on",
                                            actual=log_disconnections)
            else:
                return self._create_fail_result(control, 
                                            f"Disconnection logging is not enabled: {log_disconnections}",
                                            expected="on",
                                            actual=log_disconnections)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking log_disconnections: {str(e)}")

    def _check_log_error_verbosity(self, control: CISControl) -> ControlResult:
        """Check log_error_verbosity setting"""
        try:
            log_error_verbosity = self.db.get_setting('log_error_verbosity')

            if not log_error_verbosity:
                return self._create_fail_result(control, 
                                            "Could not retrieve log_error_verbosity setting",
                                            expected="verbose",
                                            actual="NULL")

            verbose_levels = ['terse', 'default', 'verbose']
            if log_error_verbosity.lower() in verbose_levels:
                return self._create_pass_result(control, 
                                            "Log error verbosity correctly set to verbose",
                                            expected="verbose",
                                            actual=log_error_verbosity)
            else:
                return self._create_fail_result(control, 
                                            f"Log error verbosity not set to verbose: {log_error_verbosity}",
                                            expected="verbose",
                                            actual=log_error_verbosity)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking log_error_verbosity: {str(e)}")

    def _check_log_hostname(self, control: CISControl) -> ControlResult:
        """Check log_hostname setting is disabled"""
        try:
            log_hostname = self.db.get_setting('log_hostname')

            if not log_hostname:
                return self._create_fail_result(control, 
                                            "Could not retrieve log_hostname setting",
                                            expected="off",
                                            actual="NULL")

            if log_hostname.lower() == 'off':
                return self._create_pass_result(control, 
                                            "Log hostname correctly disabled",
                                            expected="off",
                                            actual=log_hostname)
            else:
                return self._create_fail_result(control, 
                                            f"Log hostname should be disabled: {log_hostname}",
                                            expected="off",
                                            actual=log_hostname)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking log_hostname: {str(e)}")

    def _check_log_statement(self, control: CISControl) -> ControlResult:
        """Check log_statement setting"""
        try:
            log_statement = self.db.get_setting('log_statement')

            if not log_statement:
                return self._create_fail_result(control, 
                                            "Could not retrieve log_statement setting",
                                            expected="ddl, mod, or all",
                                            actual="NULL")

            if log_statement.lower() == 'none':
                return self._create_fail_result(control, 
                                            "Statement logging is disabled - security risk",
                                            expected="ddl, mod, or all",
                                            actual=log_statement)
            else:
                acceptable_values = ['ddl', 'mod', 'all']
                if log_statement.lower() in acceptable_values:
                    return self._create_pass_result(control, 
                                                f"Statement logging properly configured: {log_statement}",
                                                expected="ddl, mod, or all",
                                                actual=log_statement)
                else:
                    return self._create_warn_result(control, 
                                                f"Statement logging set to non-standard value: {log_statement}",
                                                expected="ddl, mod, or all",
                                                actual=log_statement)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking log_statement: {str(e)}")

    def _check_log_timezone(self, control: CISControl) -> ControlResult:
        """Check log_timezone setting"""
        try:
            log_timezone = self.db.get_setting('log_timezone')

            if not log_timezone:
                return self._create_fail_result(control, 
                                            "Could not retrieve log_timezone setting",
                                            expected="UTC or GMT",
                                            actual="NULL")

            acceptable_timezones = ['utc', 'gmt', 'universal']

            if log_timezone.lower() in acceptable_timezones:
                return self._create_pass_result(control, 
                                            f"Log timezone properly set: {log_timezone}",
                                            expected="UTC or GMT",
                                            actual=log_timezone)
            else:
                return self._create_fail_result(control, 
                                            f"Log timezone not set to UTC/GMT: {log_timezone}",
                                            expected="UTC or GMT",
                                            actual=log_timezone)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking log_timezone: {str(e)}")

    def _check_audit_extension_enabled(self, control: CISControl) -> ControlResult:
        """Check pgAudit extension is enabled and configured"""
        try:
            shared_preload_libraries = self.db.get_setting('shared_preload_libraries')

            if not shared_preload_libraries:
                return self._create_fail_result(control, 
                                            "Could not retrieve shared_preload_libraries setting",
                                            expected="Contains pgaudit",
                                            actual="NULL")

            libraries = [lib.strip().lower() for lib in shared_preload_libraries.split(',')]

            if 'pgaudit' not in libraries:
                return self._create_fail_result(control, 
                                            f"pgAudit extension not found in shared_preload_libraries: {shared_preload_libraries}",
                                            expected="pgaudit in shared_preload_libraries",
                                            actual=shared_preload_libraries)

            pgaudit_log = self.db.get_setting('pgaudit.log')

            if not pgaudit_log:
                return self._create_warn_result(control, 
                                            "pgAudit loaded but pgaudit.log setting not accessible",
                                            expected="Configured audit components",
                                            actual="pgaudit.log not readable")

            if pgaudit_log.lower() == 'none':
                return self._create_fail_result(control, 
                                            "pgAudit is loaded but no audit components are enabled",
                                            expected="Audit components enabled (READ,WRITE,FUNCTION,ROLE,DDL,MISC)",
                                            actual=f"pgaudit.log = {pgaudit_log}")
            else:
                return self._create_pass_result(control, 
                                            f"pgAudit properly configured with components: {pgaudit_log}",
                                            expected="Audit components enabled",
                                            actual=f"pgaudit.log = {pgaudit_log}")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking audit extension: {str(e)}")
