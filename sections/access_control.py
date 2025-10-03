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
                return self._check_ycql_auth_enabled(control)
            elif control_id.startswith("5.2"):
                return self._check_default_password_changed(control)
            elif control_id.startswith("5.3"):
                return self._check_separate_cassandra_superuser_roles(control)
            elif control_id.startswith("5.4"):
                return self._check_roles_privileges(control)
            elif control_id.startswith("5.5"):
                return self._check_ycql_listens_authorized_interface(control)
            else:
                return self._check_generic_access_control(control)
        except Exception as e:
            return self._create_fail_result(control, f"Error during access control check: {str(e)}")


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

    def _check_ycql_auth_enabled(self, control: CISControl) -> ControlResult:
        """Check that authentication is enabled for YCQL interface of the YugabyteDB"""
        return self._create_skip_result(control, "⏳ This check has not been implemented yet.")

    def _check_default_password_changed(self, control: CISControl) -> ControlResult:
        """Check that the default password changed for the cassandra role"""
        return self._create_skip_result(control, "⏳ This check has not been implemented yet.")

    def _check_separate_cassandra_superuser_roles(self, control: CISControl) -> ControlResult:
        """Check the cassandra and superuser roles are separate"""
        return self._create_skip_result(control, "⏳ This check has not been implemented yet.")

    def _check_ycql_listens_authorized_interface(self, control: CISControl) -> ControlResult:
        """Check that YCQL only listens for network connections on authorized interfaces"""
        return self._create_skip_result(control, "⏳ This check has not been implemented yet.")

    def _check_roles_privileges(self, control: CISControl) -> ControlResult:
        """Check there are no unnecessary roles or excessive privileges"""
        return self._create_skip_result(control, "⏳ This check has not been implemented yet.")
