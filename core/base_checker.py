"""
Base checker class for CIS control checks
"""

from abc import ABC, abstractmethod

from core.db_connector import YugabyteConnector
from core.models import CISControl, ControlResult, ControlStatus


class BaseChecker(ABC):
    """Base class for all section checkers"""

    def __init__(self, db_connector: YugabyteConnector):
        self.db = db_connector

    @abstractmethod
    def check_control(self, control: CISControl) -> ControlResult:
        """Check a specific control - must be implemented by subclasses"""
        pass

    def _create_pass_result(self, control: CISControl, message: str, expected: str = None, actual: str = None) -> ControlResult:
        """Create a PASS result"""
        return ControlResult(
            control_id=control.control_id,
            title=control.title,
            status=ControlStatus.PASS,
            message=message,
            section=control.section,
            profile_level=control.profile_applicability[0] if control.profile_applicability else "",
            audit_command=control.audit,
            expected=expected,
            actual=actual
        )

    def _create_fail_result(self, control: CISControl, message: str, expected: str = None, actual: str = None) -> ControlResult:
        """Create a FAIL result"""
        return ControlResult(
            control_id=control.control_id,
            title=control.title,
            status=ControlStatus.FAIL,
            message=message,
            section=control.section,
            profile_level=control.profile_applicability[0] if control.profile_applicability else "",
            remediation=control.remediation,
            audit_command=control.audit,
            impact=control.impact,
            expected=expected,
            actual=actual
        )

    def _create_warn_result(self, control: CISControl, message: str, expected: str = None, actual: str = None) -> ControlResult:
        """Create a WARN result"""
        return ControlResult(
            control_id=control.control_id,
            title=control.title,
            status=ControlStatus.WARN,
            message=message,
            section=control.section,
            profile_level=control.profile_applicability[0] if control.profile_applicability else "",
            remediation=control.remediation,
            audit_command=control.audit,
            expected=expected,
            actual=actual
        )

    def _create_info_result(self, control: CISControl, message: str, expected: str = None, actual: str = None) -> ControlResult:
        """Create an INFO result"""
        return ControlResult(
            control_id=control.control_id,
            title=control.title,
            status=ControlStatus.INFO,
            message=message,
            section=control.section,
            profile_level=control.profile_applicability[0] if control.profile_applicability else "",
            audit_command=control.audit,
            expected=expected,
            actual=actual
        )

    def _create_skip_result(self, control: CISControl, message: str) -> ControlResult:
        """Create a SKIP result"""
        return ControlResult(
            control_id=control.control_id,
            title=control.title,
            status=ControlStatus.SKIP,
            message=message,
            section=control.section,
            profile_level=control.profile_applicability[0] if control.profile_applicability else "",
            audit_command=control.audit
        )

    def _extract_setting_name_from_audit(self, audit_command: str) -> str:
        """Extract setting name from SHOW command in audit"""
        if 'SHOW ' in audit_command.upper():
            # Extract setting name from "SHOW setting_name;"
            parts = audit_command.upper().split('SHOW ')
            if len(parts) > 1:
                setting = parts[1].split(';')[0].strip()
                return setting.lower()
        return ""

    def _check_setting_value(self, control: CISControl, expected_values: list, setting_name: str = None) -> ControlResult:
        """Generic method to check if a setting matches expected values"""
        if not setting_name:
            setting_name = self._extract_setting_name_from_audit(control.audit)

        if not setting_name:
            return self._create_fail_result(control, "Could not determine setting name from audit command")

        actual_value = self.db.get_setting(setting_name)

        if actual_value is None:
            return self._create_fail_result(control, f"Could not retrieve {setting_name} setting",
                                            expected=str(expected_values), actual="NULL")

        if actual_value in expected_values:
            return self._create_pass_result(control, f"{setting_name} is properly configured: {actual_value}",
                                            expected=str(expected_values), actual=actual_value)
        else:
            return self._create_fail_result(control, f"{setting_name} is not properly configured: {actual_value}",
                                            expected=str(expected_values), actual=actual_value)

    def _check_boolean_setting(self, control: CISControl, expected_value: bool, setting_name: str = None) -> ControlResult:
        """Check if a boolean setting matches expected value"""
        if not setting_name:
            setting_name = self._extract_setting_name_from_audit(control.audit)

        if not setting_name:
            return self._create_fail_result(control, "Could not determine setting name from audit command")

        actual_value = self.db.get_setting(setting_name)

        if actual_value is None:
            return self._create_fail_result(control, f"Could not retrieve {setting_name} setting",
                                            expected=str(expected_value), actual="NULL")

        # Convert string to boolean
        actual_bool = actual_value.lower() in ('on', 'true', '1', 'yes')

        if actual_bool == expected_value:
            return self._create_pass_result(control, f"{setting_name} is properly configured: {actual_value}",
                                            expected=str(expected_value), actual=actual_value)
        else:
            return self._create_fail_result(control, f"{setting_name} is not properly configured: {actual_value}",
                                            expected=str(expected_value), actual=actual_value)
