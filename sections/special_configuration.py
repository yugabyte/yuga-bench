"""
Special Configuration Considerations section checker for YugabyteDB CIS Benchmark
"""

import logging

from core.base_checker import BaseChecker
from core.models import CISControl, ControlResult


class SpecialConfigurationChecker(BaseChecker):
    """Checker for Special Configuration Considerations section controls"""

    def check_control(self, control: CISControl) -> ControlResult:
        """Route control check to appropriate method"""
        control_id = control.control_id

        try:
            if control_id.startswith("8.1"):
                return self._check_extensions_configuration(control)
            elif control_id.startswith("8.2"):
                return self._check_cluster_configuration(control)
            elif control_id.startswith("8.3"):
                return self._check_performance_configuration(control)
            elif control_id.startswith("8.4"):
                return self._check_security_configuration(control)
            else:
                return self._check_generic_special_configuration(control)
        except Exception as e:
            return self._create_fail_result(control, f"Error during special configuration check: {str(e)}")

    def _check_extensions_configuration(self, control: CISControl) -> ControlResult:
        """Check extensions and modules configuration"""
        try:
            if "available_extensions" in control.audit.lower():
                return self._check_available_extensions(control)
            elif "installed_extensions" in control.audit.lower():
                return self._check_installed_extensions(control)
            else:
                return self._check_generic_extension_setting(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking extensions configuration: {str(e)}")

    def _check_available_extensions(self, control: CISControl) -> ControlResult:
        """Check available extensions"""
        try:
            extensions_query = "SELECT name FROM pg_available_extensions ORDER BY name;"
            extensions = self.db.execute_query(extensions_query)

            if not extensions:
                return self._create_warn_result(control, "Could not retrieve available extensions")

            extension_names = [ext['name'] for ext in extensions]
            extension_count = len(extension_names)

            # Check for potentially risky extensions
            risky_extensions = ['dblink', 'file_fdw', 'adminpack', 'xml2']
            found_risky = [ext for ext in extension_names if ext in risky_extensions]

            if found_risky:
                return self._create_warn_result(control,
                                                f"Potentially risky extensions available: {', '.join(found_risky[:5])}",
                                                expected="Minimal extensions available",
                                                actual=f"{extension_count} extensions, risky: {len(found_risky)}")
            else:
                return self._create_pass_result(control,
                                                f"{extension_count} extensions available, no obviously risky extensions found",
                                                expected="Secure extensions only",
                                                actual=f"{extension_count} extensions")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking available extensions: {str(e)}")

    def _check_installed_extensions(self, control: CISControl) -> ControlResult:
        """Check installed extensions"""
        try:
            installed_query = "SELECT extname, extversion FROM pg_extension ORDER BY extname;"
            installed = self.db.execute_query(installed_query)

            if not installed or len(installed) == 0:
                return self._create_info_result(control,
                                                "No extensions installed",
                                                expected="Minimal extensions",
                                                actual="0 extensions")

            extension_info = [(ext['extname'], ext['extversion']) for ext in installed]
            extension_names = [ext[0] for ext in extension_info]

            # Check for potentially risky installed extensions
            risky_extensions = ['dblink', 'file_fdw', 'adminpack', 'xml2', 'plpython3u', 'plperlu']
            found_risky = [name for name in extension_names if name in risky_extensions]

            extension_list = ', '.join([f"{name}({version})" for name, version in extension_info[:5]])
            if len(extension_info) > 5:
                extension_list += f" ... and {len(extension_info) - 5} more"

            if found_risky:
                return self._create_fail_result(control,
                                                f"Risky extensions installed: {', '.join(found_risky)}",
                                                expected="No risky extensions",
                                                actual=extension_list)
            else:
                return self._create_pass_result(control,
                                                f"Extensions installed: {extension_list}",
                                                expected="Safe extensions only",
                                                actual=extension_list)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking installed extensions: {str(e)}")

    def _check_cluster_configuration(self, control: CISControl) -> ControlResult:
        """Check cluster-specific configuration"""
        try:
            if "cluster_name" in control.audit.lower():
                return self._check_cluster_name(control)
            elif "wal_level" in control.audit.lower():
                return self._check_wal_level(control)
            elif "max_wal_senders" in control.audit.lower():
                return self._check_max_wal_senders(control)
            else:
                return self._check_generic_cluster_setting(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking cluster configuration: {str(e)}")

    def _check_cluster_name(self, control: CISControl) -> ControlResult:
        """Check cluster name configuration"""
        cluster_name = self.db.get_setting('cluster_name')

        if not cluster_name or cluster_name.strip() == '':
            return self._create_warn_result(control,
                                            "Cluster name is not set - consider setting for identification",
                                            expected="Descriptive cluster name",
                                            actual="Not set")
        else:
            return self._create_pass_result(control,
                                            f"Cluster name configured: {cluster_name}",
                                            expected="Descriptive cluster name",
                                            actual=cluster_name)

    def _check_wal_level(self, control: CISControl) -> ControlResult:
        """Check WAL level configuration"""
        wal_level = self.db.get_setting('wal_level')

        if not wal_level:
            return self._create_fail_result(control, "Could not retrieve wal_level setting")

        acceptable_levels = ['replica', 'logical']

        if wal_level in acceptable_levels:
            return self._create_pass_result(control,
                                            f"WAL level appropriately configured: {wal_level}",
                                            expected="replica or logical",
                                            actual=wal_level)
        elif wal_level == 'minimal':
            return self._create_warn_result(control,
                                            "WAL level set to minimal - may limit backup and replication options",
                                            expected="replica or logical",
                                            actual=wal_level)
        else:
            return self._create_info_result(control,
                                            f"WAL level configured: {wal_level}",
                                            actual=wal_level)

    def _check_max_wal_senders(self, control: CISControl) -> ControlResult:
        """Check max_wal_senders configuration"""
        max_wal_senders = self.db.get_setting('max_wal_senders')

        if not max_wal_senders:
            return self._create_fail_result(control, "Could not retrieve max_wal_senders setting")

        try:
            senders_count = int(max_wal_senders)

            if senders_count == 0:
                return self._create_warn_result(control,
                                                "WAL senders disabled - replication not possible",
                                                expected="Appropriate for replication needs",
                                                actual="0")
            elif senders_count > 0:
                return self._create_pass_result(control,
                                                f"WAL senders configured: {max_wal_senders}",
                                                expected="Appropriate for replication needs",
                                                actual=max_wal_senders)
            else:
                return self._create_fail_result(control, f"Invalid max_wal_senders value: {max_wal_senders}")
        except (ValueError, TypeError):
            return self._create_fail_result(control, f"Invalid max_wal_senders value: {max_wal_senders}")

    def _check_performance_configuration(self, control: CISControl) -> ControlResult:
        """Check performance-related configuration"""
        try:
            if "random_page_cost" in control.audit.lower():
                return self._check_random_page_cost(control)
            elif "effective_cache_size" in control.audit.lower():
                return self._check_effective_cache_size(control)
            elif "default_statistics_target" in control.audit.lower():
                return self._check_default_statistics_target(control)
            else:
                return self._check_generic_performance_setting(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking performance configuration: {str(e)}")

    def _check_random_page_cost(self, control: CISControl) -> ControlResult:
        """Check random_page_cost setting"""
        random_page_cost = self.db.get_setting('random_page_cost')

        if not random_page_cost:
            return self._create_fail_result(control, "Could not retrieve random_page_cost setting")

        try:
            cost_value = float(random_page_cost)

            # For SSDs, values between 1.1-2.0 are typical
            if 1.0 <= cost_value <= 2.0:
                return self._create_pass_result(control,
                                                f"Random page cost appropriately configured for SSD: {random_page_cost}",
                                                expected="1.0-2.0 for SSD storage",
                                                actual=random_page_cost)
            elif cost_value == 4.0:
                return self._create_info_result(control,
                                                f"Random page cost set to default: {random_page_cost} (consider tuning for SSD)",
                                                expected="Tuned for storage type",
                                                actual=random_page_cost)
            else:
                return self._create_info_result(control,
                                                f"Random page cost configured: {random_page_cost}",
                                                actual=random_page_cost)
        except (ValueError, TypeError):
            return self._create_fail_result(control, f"Invalid random_page_cost value: {random_page_cost}")

    def _check_effective_cache_size(self, control: CISControl) -> ControlResult:
        """Check effective_cache_size setting"""
        effective_cache_size = self.db.get_setting('effective_cache_size')

        if not effective_cache_size:
            return self._create_fail_result(control, "Could not retrieve effective_cache_size setting")

        return self._create_info_result(control,
                                        f"Effective cache size configured: {effective_cache_size}",
                                        expected="Appropriate for available system memory",
                                        actual=effective_cache_size)

    def _check_default_statistics_target(self, control: CISControl) -> ControlResult:
        """Check default_statistics_target setting"""
        default_statistics_target = self.db.get_setting('default_statistics_target')

        if not default_statistics_target:
            return self._create_fail_result(control, "Could not retrieve default_statistics_target setting")

        try:
            target_value = int(default_statistics_target)

            if target_value < 10:
                return self._create_warn_result(control,
                                                f"Very low statistics target: {default_statistics_target}",
                                                expected="10-1000",
                                                actual=default_statistics_target)
            elif 10 <= target_value <= 1000:
                return self._create_pass_result(control,
                                                f"Statistics target reasonably configured: {default_statistics_target}",
                                                expected="10-1000",
                                                actual=default_statistics_target)
            else:
                return self._create_info_result(control,
                                                f"Statistics target configured: {default_statistics_target}",
                                                actual=default_statistics_target)
        except (ValueError, TypeError):
            return self._create_fail_result(control, f"Invalid default_statistics_target value: {default_statistics_target}")

    def _check_security_configuration(self, control: CISControl) -> ControlResult:
        """Check security-related configuration"""
        try:
            if "row_security" in control.audit.lower():
                return self._check_row_security(control)
            elif "ssl_prefer_server_ciphers" in control.audit.lower():
                return self._check_ssl_prefer_server_ciphers(control)
            else:
                return self._check_generic_security_setting(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking security configuration: {str(e)}")

    def _check_row_security(self, control: CISControl) -> ControlResult:
        """Check row_security setting"""
        row_security = self.db.get_setting('row_security')

        if row_security == 'on':
            return self._create_pass_result(control,
                                            "Row-level security is enabled",
                                            expected="on",
                                            actual=row_security)
        else:
            return self._create_info_result(control,
                                            f"Row-level security: {row_security}",
                                            expected="on (if RLS policies are used)",
                                            actual=row_security)

    def _check_ssl_prefer_server_ciphers(self, control: CISControl) -> ControlResult:
        """Check ssl_prefer_server_ciphers setting"""
        ssl_prefer_server_ciphers = self.db.get_setting('ssl_prefer_server_ciphers')

        if ssl_prefer_server_ciphers == 'on':
            return self._create_pass_result(control,
                                            "Server cipher preferences enabled",
                                            expected="on",
                                            actual=ssl_prefer_server_ciphers)
        else:
            return self._create_warn_result(control,
                                            "Server cipher preferences not enabled - may allow weak ciphers",
                                            expected="on",
                                            actual=ssl_prefer_server_ciphers or "off")

    def _check_generic_extension_setting(self, control: CISControl) -> ControlResult:
        """Generic extension setting check"""
        return self._create_skip_result(control, "Generic extension configuration - manual verification required")

    def _check_generic_cluster_setting(self, control: CISControl) -> ControlResult:
        """Generic cluster setting check"""
        setting_name = self._extract_setting_name_from_audit(control.audit)

        # TODO: Implement this function.
        return self._create_warn_result(control, "Verify cluster settings",
                                        expected="on", actual=ssl_prefer_server_ciphers or "off")
