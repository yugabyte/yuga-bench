"""
Access Control and Password Policies section checker for YugabyteDB CIS Benchmark
"""

import logging

from core.base_checker import BaseChecker
from core.models import CISControl, ControlResult


class AccessControlChecker(BaseChecker):
    """Checker for Access Control and Password Policies section controls"""

    def check_control(self, control: CISControl) -> ControlResult:
        """Route control check to appropriate method"""
        control_id = control.control_id

        try:
            if control_id.startswith("5.1"):
                return self._check_password_policies(control)
            elif control_id.startswith("5.2"):
                return self._check_account_lockout(control)
            elif control_id.startswith("5.3"):
                return self._check_session_management(control)
            elif control_id.startswith("5.4"):
                return self._check_privilege_escalation(control)
            else:
                return self._check_generic_access_control(control)
        except Exception as e:
            return self._create_fail_result(control, f"Error during access control check: {str(e)}")

    def _check_password_policies(self, control: CISControl) -> ControlResult:
        """Check password policy configurations"""
        try:
            # Check password encryption method
            password_encryption = self.db.get_setting('password_encryption')

            if not password_encryption:
                return self._create_fail_result(control, "Could not retrieve password encryption setting")

            if password_encryption == 'scram-sha-256':
                return self._create_pass_result(control,
                                                "Strong password encryption enabled: SCRAM-SHA-256",
                                                expected="scram-sha-256",
                                                actual=password_encryption)
            elif password_encryption == 'md5':
                return self._create_warn_result(control,
                                                "Password encryption using MD5 - consider upgrading to SCRAM-SHA-256",
                                                expected="scram-sha-256",
                                                actual=password_encryption)
            else:
                return self._create_fail_result(control,
                                                f"Weak password encryption method: {password_encryption}",
                                                expected="scram-sha-256",
                                                actual=password_encryption)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking password policies: {str(e)}")

    def _check_account_lockout(self, control: CISControl) -> ControlResult:
        """Check account lockout policies"""
        try:
            # YugabyteDB doesn't have built-in account lockout policies like some other databases
            # This would typically be handled at the application or connection pooler level

            return self._create_skip_result(control,
                                            "Account lockout policies not natively supported in YugabyteDB - implement at application level")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking account lockout: {str(e)}")

    def _check_session_management(self, control: CISControl) -> ControlResult:
        """Check session management settings"""
        try:
            if "idle_in_transaction_session_timeout" in control.audit.lower():
                return self._check_idle_session_timeout(control)
            elif "statement_timeout" in control.audit.lower():
                return self._check_statement_timeout(control)
            elif "tcp_keepalives" in control.audit.lower():
                return self._check_tcp_keepalives(control)
            else:
                return self._check_generic_session_setting(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking session management: {str(e)}")

    def _check_idle_session_timeout(self, control: CISControl) -> ControlResult:
        """Check idle session timeout setting"""
        setting_value = self.db.get_setting('idle_in_transaction_session_timeout')

        if not setting_value:
            return self._create_fail_result(control, "Could not retrieve idle_in_transaction_session_timeout setting")

        # Convert to integer (value is in milliseconds)
        try:
            timeout_ms = int(setting_value)
            if timeout_ms == 0:
                return self._create_warn_result(control,
                                                "Idle transaction session timeout is disabled",
                                                expected="Non-zero timeout (e.g., 30000ms = 30s)",
                                                actual="0 (disabled)")
            elif timeout_ms > 0:
                timeout_seconds = timeout_ms / 1000
                return self._create_pass_result(control,
                                                f"Idle transaction session timeout configured: {timeout_seconds}s",
                                                expected="Reasonable timeout value",
                                                actual=f"{timeout_seconds}s")
            else:
                return self._create_fail_result(control,
                                                f"Invalid idle transaction session timeout: {timeout_ms}",
                                                expected="Positive timeout value",
                                                actual=str(timeout_ms))
        except (ValueError, TypeError):
            return self._create_fail_result(control, f"Invalid timeout value: {setting_value}")

    def _check_statement_timeout(self, control: CISControl) -> ControlResult:
        """Check statement timeout setting"""
        setting_value = self.db.get_setting('statement_timeout')

        if not setting_value:
            return self._create_fail_result(control, "Could not retrieve statement_timeout setting")

        try:
            timeout_ms = int(setting_value)
            if timeout_ms == 0:
                return self._create_warn_result(control,
                                                "Statement timeout is disabled - long-running queries may impact system",
                                                expected="Non-zero timeout for production systems",
                                                actual="0 (disabled)")
            else:
                timeout_seconds = timeout_ms / 1000
                return self._create_pass_result(control,
                                                f"Statement timeout configured: {timeout_seconds}s",
                                                expected="Reasonable timeout value",
                                                actual=f"{timeout_seconds}s")
        except (ValueError, TypeError):
            return self._create_fail_result(control, f"Invalid statement timeout value: {setting_value}")

    def _check_tcp_keepalives(self, control: CISControl) -> ControlResult:
        """Check TCP keepalive settings"""
        keepalive_settings = [
            'tcp_keepalives_idle',
            'tcp_keepalives_interval',
            'tcp_keepalives_count'
        ]

        settings_info = {}
        for setting in keepalive_settings:
            value = self.db.get_setting(setting)
            settings_info[setting] = value

        # Check if any keepalive settings are configured
        configured_settings = {k: v for k, v in settings_info.items() if v and v != '0'}

        if configured_settings:
            settings_str = ', '.join([f"{k}={v}" for k, v in configured_settings.items()])
            return self._create_pass_result(control,
                                            f"TCP keepalive settings configured: {settings_str}",
                                            expected="TCP keepalives enabled",
                                            actual=settings_str)
        else:
            return self._create_warn_result(control,
                                            "TCP keepalive settings not configured - may affect connection management",
                                            expected="TCP keepalives enabled",
                                            actual="All keepalive settings disabled or default")

    def _check_privilege_escalation(self, control: CISControl) -> ControlResult:
        """Check for privilege escalation vulnerabilities"""
        try:
            # Check for users with CREATEROLE privilege who are not superusers
            createrole_query = """
            SELECT rolname FROM pg_roles
            WHERE rolcreaterole = true AND rolsuper = false;
            """

            createrole_users = self.db.execute_query(createrole_query)

            if createrole_users and len(createrole_users) > 0:
                user_names = [user['rolname'] for user in createrole_users]
                return self._create_warn_result(control,
                                                f"Non-superuser accounts with CREATEROLE privilege: {', '.join(user_names)}",
                                                expected="Limited CREATEROLE privileges",
                                                actual=f"{len(user_names)} accounts with CREATEROLE")
            else:
                return self._create_pass_result(control,
                                                "No non-superuser accounts have CREATEROLE privilege",
                                                expected="Limited CREATEROLE privileges",
                                                actual="No privilege escalation risks identified")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking privilege escalation: {str(e)}")

    def _check_generic_session_setting(self, control: CISControl) -> ControlResult:
        """Generic session setting check"""
        setting_name = self._extract_setting_name_from_audit(control.audit)

        if setting_name:
            setting_value = self.db.get_setting(setting_name)
            return self._create_info_result(control,
                                            f"Session setting {setting_name}: {setting_value}",
                                            actual=str(setting_value))
        else:
            return self._create_skip_result(control, "Generic session management check - manual verification required")

    def _check_generic_access_control(self, control: CISControl) -> ControlResult:
        """Generic access control check"""
        setting_name = self._extract_setting_name_from_audit(control.audit)

        if setting_name:
            setting_value = self.db.get_setting(setting_name)
            return self._create_info_result(control,
                                            f"Access control setting {setting_name}: {setting_value}",
                                            actual=str(setting_value))
        else:
            return self._create_skip_result(control, "Generic access control check - manual verification required")
