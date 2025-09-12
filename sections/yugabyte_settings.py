"""
YugabyteDB Settings section checker for YugabyteDB CIS Benchmark
"""

import logging

from core.base_checker import BaseChecker
from core.models import CISControl, ControlResult


class YugabyteSettingsChecker(BaseChecker):
    """Checker for YugabyteDB Settings section controls"""

    def check_control(self, control: CISControl) -> ControlResult:
        """Route control check to appropriate method"""
        control_id = control.control_id

        try:
            if control_id.startswith("7.1"):
                return self._check_shared_preload_libraries(control)
            elif control_id.startswith("7.2"):
                return self._check_runtime_parameters(control)
            elif control_id.startswith("7.3"):
                return self._check_memory_settings(control)
            elif control_id.startswith("7.4"):
                return self._check_maintenance_settings(control)
            else:
                return self._check_generic_yugabyte_setting(control)
        except Exception as e:
            return self._create_fail_result(control, f"Error during YugabyteDB settings check: {str(e)}")

    def _check_shared_preload_libraries(self, control: CISControl) -> ControlResult:
        """Check shared preload libraries configuration"""
        try:
            shared_preload_libs = self.db.get_setting('shared_preload_libraries')

            if not shared_preload_libs or shared_preload_libs.strip() == '':
                return self._create_info_result(control,
                                                "No shared preload libraries configured",
                                                expected="Security-relevant extensions only",
                                                actual="None")

            # Split and analyze libraries
            libraries = [lib.strip() for lib in shared_preload_libs.split(',')]

            # Check for potentially risky libraries
            risky_libs = ['dblink', 'file_fdw', 'plpython3u', 'plperlu', 'plpgsql']
            found_risky = [lib for lib in libraries if any(risky in lib.lower() for risky in risky_libs)]

            # Check for security-related extensions
            security_libs = ['pg_audit', 'passwordcheck', 'auth_delay']
            found_security = [lib for lib in libraries if any(sec in lib.lower() for sec in security_libs)]

            if found_risky:
                return self._create_warn_result(control,
                                                f"Potentially risky libraries loaded: {', '.join(found_risky)}",
                                                expected="Security-relevant extensions only",
                                                actual=shared_preload_libs)
            elif found_security:
                return self._create_pass_result(control,
                                                f"Security-related libraries configured: {', '.join(found_security)}",
                                                expected="Security-relevant extensions",
                                                actual=shared_preload_libs)
            else:
                return self._create_info_result(control,
                                                f"Shared preload libraries: {shared_preload_libs}",
                                                actual=shared_preload_libs)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking shared preload libraries: {str(e)}")

    def _check_runtime_parameters(self, control: CISControl) -> ControlResult:
        """Check runtime parameter configurations"""
        try:
            if "enable_seqscan" in control.audit.lower():
                return self._check_enable_seqscan(control)
            elif "log_statement_stats" in control.audit.lower():
                return self._check_log_statement_stats(control)
            elif "log_parser_stats" in control.audit.lower():
                return self._check_log_parser_stats(control)
            elif "log_planner_stats" in control.audit.lower():
                return self._check_log_planner_stats(control)
            elif "log_executor_stats" in control.audit.lower():
                return self._check_log_executor_stats(control)
            else:
                return self._check_generic_runtime_parameter(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking runtime parameters: {str(e)}")

    def _check_enable_seqscan(self, control: CISControl) -> ControlResult:
        """Check enable_seqscan setting"""
        enable_seqscan = self.db.get_setting('enable_seqscan')

        if enable_seqscan == 'off':
            return self._create_warn_result(control,
                                            "Sequential scans are disabled - may cause performance issues",
                                            expected="on (unless specifically required)",
                                            actual=enable_seqscan)
        else:
            return self._create_pass_result(control,
                                            f"Sequential scans enabled: {enable_seqscan}",
                                            expected="on (default)",
                                            actual=enable_seqscan)

    def _check_log_statement_stats(self, control: CISControl) -> ControlResult:
        """Check log_statement_stats setting"""
        return self._check_boolean_setting(control, False, 'log_statement_stats')

    def _check_log_parser_stats(self, control: CISControl) -> ControlResult:
        """Check log_parser_stats setting"""
        return self._check_boolean_setting(control, False, 'log_parser_stats')

    def _check_log_planner_stats(self, control: CISControl) -> ControlResult:
        """Check log_planner_stats setting"""
        return self._check_boolean_setting(control, False, 'log_planner_stats')

    def _check_log_executor_stats(self, control: CISControl) -> ControlResult:
        """Check log_executor_stats setting"""
        return self._check_boolean_setting(control, False, 'log_executor_stats')

    def _check_memory_settings(self, control: CISControl) -> ControlResult:
        """Check memory-related settings"""
        try:
            if "shared_buffers" in control.audit.lower():
                return self._check_shared_buffers(control)
            elif "work_mem" in control.audit.lower():
                return self._check_work_mem(control)
            elif "maintenance_work_mem" in control.audit.lower():
                return self._check_maintenance_work_mem(control)
            else:
                return self._check_generic_memory_setting(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking memory settings: {str(e)}")

    def _check_shared_buffers(self, control: CISControl) -> ControlResult:
        """Check shared_buffers setting"""
        shared_buffers = self.db.get_setting('shared_buffers')

        if not shared_buffers:
            return self._create_fail_result(control, "Could not retrieve shared_buffers setting")

        return self._create_info_result(control,
                                        f"Shared buffers configured: {shared_buffers}",
                                        expected="Appropriate for system memory",
                                        actual=shared_buffers)

    def _check_work_mem(self, control: CISControl) -> ControlResult:
        """Check work_mem setting"""
        work_mem = self.db.get_setting('work_mem')

        if not work_mem:
            return self._create_fail_result(control, "Could not retrieve work_mem setting")

        return self._create_info_result(control,
                                        f"Work memory configured: {work_mem}",
                                        expected="Appropriate for workload",
                                        actual=work_mem)

    def _check_maintenance_work_mem(self, control: CISControl) -> ControlResult:
        """Check maintenance_work_mem setting"""
        maintenance_work_mem = self.db.get_setting('maintenance_work_mem')

        if not maintenance_work_mem:
            return self._create_fail_result(control, "Could not retrieve maintenance_work_mem setting")

        return self._create_info_result(control,
                                        f"Maintenance work memory configured: {maintenance_work_mem}",
                                        expected="Appropriate for maintenance operations",
                                        actual=maintenance_work_mem)

    def _check_maintenance_settings(self, control: CISControl) -> ControlResult:
        """Check maintenance-related settings"""
        try:
            if "autovacuum" in control.audit.lower():
                return self._check_autovacuum(control)
            elif "checkpoint" in control.audit.lower():
                return self._check_checkpoint_settings(control)
            else:
                return self._check_generic_maintenance_setting(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking maintenance settings: {str(e)}")

    def _check_autovacuum(self, control: CISControl) -> ControlResult:
        """Check autovacuum settings"""
        autovacuum = self.db.get_setting('autovacuum')

        if autovacuum == 'off':
            return self._create_fail_result(control,
                                            "Autovacuum is disabled - may cause performance degradation",
                                            expected="on",
                                            actual=autovacuum)
        else:
            return self._create_pass_result(control,
                                            f"Autovacuum is enabled: {autovacuum}",
                                            expected="on",
                                            actual=autovacuum)

    def _check_checkpoint_settings(self, control: CISControl) -> ControlResult:
        """Check checkpoint-related settings"""
        if "checkpoint_completion_target" in control.audit.lower():
            setting_value = self.db.get_setting('checkpoint_completion_target')

            if setting_value:
                try:
                    completion_target = float(setting_value)
                    if 0.5 <= completion_target <= 0.9:
                        return self._create_pass_result(control,
                                                        f"Checkpoint completion target properly configured: {setting_value}",
                                                        expected="0.5-0.9",
                                                        actual=setting_value)
                    else:
                        return self._create_warn_result(control,
                                                        f"Checkpoint completion target outside recommended range: {setting_value}",
                                                        expected="0.5-0.9",
                                                        actual=setting_value)
                except (ValueError, TypeError):
                    return self._create_fail_result(control, f"Invalid checkpoint completion target: {setting_value}")
            else:
                return self._create_fail_result(control, "Could not retrieve checkpoint_completion_target")
        else:
            return self._check_generic_yugabyte_setting(control)

    def _check_generic_runtime_parameter(self, control: CISControl) -> ControlResult:
        """Generic runtime parameter check"""
        setting_name = self._extract_setting_name_from_audit(control.audit)

        if setting_name:
            setting_value = self.db.get_setting(setting_name)
            return self._create_info_result(control,
                                            f"Runtime parameter {setting_name}: {setting_value}",
                                            actual=str(setting_value))
        else:
            return self._create_skip_result(control, "Generic runtime parameter check - manual verification required")

    def _check_generic_memory_setting(self, control: CISControl) -> ControlResult:
        """Generic memory setting check"""
        setting_name = self._extract_setting_name_from_audit(control.audit)

        if setting_name:
            setting_value = self.db.get_setting(setting_name)
            return self._create_info_result(control,
                                            f"Memory setting {setting_name}: {setting_value}",
                                            actual=str(setting_value))
        else:
            return self._create_skip_result(control, "Generic memory setting check - manual verification required")

    def _check_generic_maintenance_setting(self, control: CISControl) -> ControlResult:
        """Generic maintenance setting check"""
        setting_name = self._extract_setting_name_from_audit(control.audit)

        if setting_name:
            setting_value = self.db.get_setting(setting_name)
            return self._create_info_result(control,
                                            f"Maintenance setting {setting_name}: {setting_value}",
                                            actual=str(setting_value))
        else:
            return self._create_skip_result(control, "Generic maintenance setting check - manual verification required")

    def _check_generic_yugabyte_setting(self, control: CISControl) -> ControlResult:
        """Generic YugabyteDB setting check"""
        setting_name = self._extract_setting_name_from_audit(control.audit)

        if setting_name:
            setting_value = self.db.get_setting(setting_name)
            return self._create_info_result(control,
                                            f"YugabyteDB setting {setting_name}: {setting_value}",
                                            actual=str(setting_value))
        else:
            return self._create_skip_result(control, "Generic YugabyteDB setting check - manual verification required")
