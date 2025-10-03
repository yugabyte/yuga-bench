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
                return self._check_backend_runtime_parameters(control)
            elif control_id.startswith("7.3"):
                return self._check_memory_settings(control)
            elif control_id.startswith("7.4"):
                return self._check_maintenance_settings(control)
            elif control_id.startswith("7.7"):
                return self._check_tls_enabled_server_to_server(control)
            elif control_id.startswith("7.8"):
                return self._check_tls_enabled_client_to_server(control)
            elif control_id.startswith("7.9"):
                return self._check_pgcrypto_installed_enabled(control)
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
                return self._create_fail_result(control,
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
            return self._create_fail_result(control,
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
                        return self._create_fail_result(control,
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

    def _check_backend_runtime_parameters(self, control: CISControl) -> ControlResult:
        """Check backend runtime parameters are configured securely"""
        try:
            # Query backend runtime parameters
            runtime_params_query = """
            SELECT name, setting FROM pg_settings 
            WHERE context IN ('backend','superuser-backend') 
            ORDER BY name;
            """

            params_result = self.db.execute_query(runtime_params_query)

            if not params_result:
                return self._create_fail_result(control, 
                                            "Could not retrieve backend runtime parameters",
                                            expected="Secure parameter settings",
                                            actual="Query failed")

            # Define expected secure values for critical parameters
            secure_settings = {
                'ignore_system_indexes': 'off',
                'jit_debugging_support': 'off',
                'jit_profiling_support': 'off',
                'log_connections': 'on',  # Should be enabled for auditing
                'log_disconnections': 'on',  # Should be enabled for auditing
                'post_auth_delay': '0'
            }

            # Convert results to dictionary for easier checking
            current_settings = {param['name']: param['setting'] for param in params_result}

            issues = []
            warnings = []
            secure_params = []

            # Check each parameter
            for param_name, expected_value in secure_settings.items():
                current_value = current_settings.get(param_name)

                if current_value is None:
                    warnings.append(f"{param_name}: not found")
                    continue

                if param_name in ['ignore_system_indexes', 'jit_debugging_support', 'jit_profiling_support']:
                    # These should be 'off' for security
                    if current_value.lower() != 'off':
                        issues.append(f"{param_name}: {current_value} (should be off)")
                    else:
                        secure_params.append(f"{param_name}: {current_value}")
                elif param_name in ['log_connections', 'log_disconnections']:
                    # These should be 'on' for auditing
                    if current_value.lower() != 'on':
                        issues.append(f"{param_name}: {current_value} (should be on for auditing)")
                    else:
                        secure_params.append(f"{param_name}: {current_value}")

                elif param_name == 'post_auth_delay':
                    # Should be 0 for normal operation
                    if current_value != '0':
                        warnings.append(f"{param_name}: {current_value} (non-zero delay)")
                    else:
                        secure_params.append(f"{param_name}: {current_value}")

            # Check for any unexpected backend parameters that might be risky
            risky_params = []
            for param in params_result:
                param_name = param['name']
                if param_name not in secure_settings:
                    # Look for potentially risky parameters
                    if any(risk_keyword in param_name.lower() for risk_keyword in 
                        ['debug', 'trace', 'dump', 'test', 'unsafe']):
                        risky_params.append(f"{param_name}: {param['setting']}")

            # Prepare result message
            all_params = [f"{p['name']}: {p['setting']}" for p in params_result]
            actual_summary = f"{len(params_result)} parameters found: " + ", ".join(all_params[:6])
            if len(all_params) > 6:
                actual_summary += f" ... and {len(all_params) - 6} more"

            # Determine result based on findings
            if issues:
                return self._create_fail_result(control, 
                                            f"Insecure runtime parameter settings found: {'; '.join(issues)}",
                                            expected="All backend parameters configured securely",
                                            actual=actual_summary)
            elif warnings or risky_params:
                warning_msg = []
                if warnings:
                    warning_msg.extend(warnings)
                if risky_params:
                    warning_msg.append(f"Potentially risky parameters: {'; '.join(risky_params)}")

                return self._create_warn_result(control, 
                                            f"Runtime parameters need review: {'; '.join(warning_msg)}",
                                            expected="All backend parameters configured securely",
                                            actual=actual_summary)
            else:
                return self._create_pass_result(control, 
                                            f"Backend runtime parameters are securely configured: {'; '.join(secure_params)}",
                                            expected="All backend parameters configured securely",
                                            actual=actual_summary)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking runtime parameters: {str(e)}")

    def _check_tls_enabled_server_to_server(self, control: CISControl) -> ControlResult:
        """Check if TLS/SSL is enabled for server-to-server communication"""
        try:
            # Check if SSL is enabled
            ssl_enabled = self.db.get_setting('ssl')

            if not ssl_enabled:
                return self._create_fail_result(control, 
                                            "Could not retrieve SSL setting",
                                            expected="on",
                                            actual="NULL")

            if ssl_enabled.lower() != 'on':
                return self._create_fail_result(control, 
                                            f"SSL/TLS is not enabled: {ssl_enabled}",
                                            expected="on",
                                            actual=ssl_enabled)

            # SSL is enabled, now check SSL certificate and key file configuration
            ssl_files_query = """
            SELECT name, setting FROM pg_settings 
            WHERE name LIKE 'ssl%file' 
            ORDER BY name;
            """

            ssl_files_result = self.db.execute_query(ssl_files_query)

            if not ssl_files_result:
                return self._create_warn_result(control, 
                                            "SSL is enabled but could not verify SSL file configuration",
                                            expected="SSL enabled with proper certificate files",
                                            actual=f"ssl = {ssl_enabled}, SSL files check failed")

            ssl_files = {row['name']: row['setting'] for row in ssl_files_result}

            cert_file = ssl_files.get('ssl_cert_file', '')
            key_file = ssl_files.get('ssl_key_file', '')
            ca_file = ssl_files.get('ssl_ca_file', '')

            config_details = []
            issues = []

            if cert_file:
                config_details.append(f"cert_file: {cert_file}")
            else:
                issues.append("ssl_cert_file not configured")

            if key_file:
                config_details.append(f"key_file: {key_file}")
            else:
                issues.append("ssl_key_file not configured")

            if ca_file:
                config_details.append(f"ca_file: {ca_file}")
            else:
                config_details.append("ca_file: not set")

            # Check for other SSL files
            for file_type in ['ssl_crl_file', 'ssl_dh_params_file']:
                if ssl_files.get(file_type):
                    config_details.append(f"{file_type}: {ssl_files[file_type]}")

            config_summary = f"ssl = {ssl_enabled}; " + "; ".join(config_details)

            # Determine result based on SSL configuration completeness
            if issues:
                return self._create_fail_result(control, 
                                            f"SSL enabled but incomplete configuration: {'; '.join(issues)}",
                                            expected="SSL enabled with certificate and key files configured",
                                            actual=config_summary)

            # Check if using default filenames (security consideration)
            using_defaults = (cert_file == 'server.crt' and key_file == 'server.key')

            if using_defaults:
                return self._create_warn_result(control, 
                                            "SSL properly enabled but using default certificate filenames",
                                            expected="SSL enabled with custom certificate filenames",
                                            actual=config_summary)
            else:
                return self._create_pass_result(control, 
                                            f"SSL/TLS properly configured for server-to-server communication",
                                            expected="SSL enabled with proper certificate configuration",
                                            actual=config_summary)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking TLS configuration: {str(e)}")

    def _check_tls_enabled_client_to_server(self, control: CISControl) -> ControlResult:
        """Check if TLS/SSL is enabled for client-to-server communication"""
        try:
            ssl_enabled = self.db.get_setting('ssl')

            if not ssl_enabled:
                return self._create_fail_result(control, 
                                            "Could not retrieve SSL setting",
                                            expected="on",
                                            actual="NULL")

            if ssl_enabled.lower() != 'on':
                return self._create_fail_result(control, 
                                            f"SSL/TLS is not enabled for client connections: {ssl_enabled}",
                                            expected="on",
                                            actual=ssl_enabled)

            # SSL is enabled, now check SSL certificate and key file configuration
            ssl_files_query = """
            SELECT name, setting FROM pg_settings 
            WHERE name LIKE 'ssl%file' 
            ORDER BY name;
            """

            ssl_files_result = self.db.execute_query(ssl_files_query)

            if not ssl_files_result:
                return self._create_warn_result(control, 
                                            "SSL is enabled but could not verify SSL certificate configuration",
                                            expected="SSL enabled with proper certificate files",
                                            actual=f"ssl = {ssl_enabled}, SSL files check failed")

            ssl_files = {row['name']: row['setting'] for row in ssl_files_result}

            cert_file = ssl_files.get('ssl_cert_file', '')
            key_file = ssl_files.get('ssl_key_file', '')
            ca_file = ssl_files.get('ssl_ca_file', '')
            crl_file = ssl_files.get('ssl_crl_file', '')
            dh_params_file = ssl_files.get('ssl_dh_params_file', '')

            # Build configuration details
            config_details = []
            critical_issues = []
            warnings = []

            # Check required files
            if cert_file:
                config_details.append(f"cert_file: {cert_file}")
            else:
                critical_issues.append("ssl_cert_file not configured")

            if key_file:
                config_details.append(f"key_file: {key_file}")
            else:
                critical_issues.append("ssl_key_file not configured")

            # Optional but recommended files
            if ca_file:
                config_details.append(f"ca_file: {ca_file}")
            else:
                warnings.append("ssl_ca_file not configured (recommended for client certificate verification)")

            # Other optional files
            if crl_file:
                config_details.append(f"crl_file: {crl_file}")

            if dh_params_file:
                config_details.append(f"dh_params_file: {dh_params_file}")

            config_summary = f"ssl = {ssl_enabled}; " + "; ".join(config_details)

            # Check for security concerns with default filenames
            security_warnings = []
            if cert_file == 'server.crt':
                security_warnings.append("using default certificate filename")
            if key_file == 'server.key':
                security_warnings.append("using default key filename")

            # Determine result based on configuration
            if critical_issues:
                return self._create_fail_result(control, 
                                            f"SSL enabled but missing required files: {'; '.join(critical_issues)}",
                                            expected="SSL enabled with certificate and key files configured",
                                            actual=config_summary)

            # SSL properly configured, check for warnings
            all_warnings = warnings + security_warnings

            if all_warnings:
                return self._create_warn_result(control, 
                                            f"SSL enabled for client connections with recommendations: {'; '.join(all_warnings)}",
                                            expected="SSL enabled with custom certificate names and CA file",
                                            actual=config_summary)
            else:
                return self._create_pass_result(control, 
                                            "SSL/TLS properly configured for client-to-server communication",
                                            expected="SSL enabled with proper certificate configuration",
                                            actual=config_summary)
        except Exception as e:
            return self._create_fail_result(control, f"Error checking client TLS configuration: {str(e)}")

    def _check_pgcrypto_installed_enabled(self, control: CISControl) -> ControlResult:
        """Check if pgcrypto extension is available and installed for data encryption"""
        try:
            available_query = "SELECT * FROM pg_available_extensions WHERE name='pgcrypto';"
            available_result = self.db.execute_query(available_query)

            if not available_result or len(available_result) == 0:
                return self._create_fail_result(control, 
                                            "pgcrypto extension is not available in this YugabyteDB installation",
                                            expected="pgcrypto available and installed",
                                            actual="pgcrypto not available")

            extension_info = available_result[0]
            name = extension_info.get('name')
            default_version = extension_info.get('default_version')
            installed_version = extension_info.get('installed_version')
            comment = extension_info.get('comment', '')

            availability_summary = f"name: {name}, default_version: {default_version}, comment: {comment}"

            # Check if pgcrypto is installed (has an installed_version)
            if installed_version and installed_version.strip():
                return self._create_pass_result(control, 
                                            f"pgcrypto extension is available and installed (version {installed_version})",
                                            expected="pgcrypto available and installed",
                                            actual=f"installed_version: {installed_version}, {availability_summary}")
            else:
                # pgcrypto is available but not installed
                return self._create_fail_result(control, 
                                            f"pgcrypto extension is available but not installed. {availability_summary}",
                                            expected="pgcrypto installed for data encryption",
                                            actual=f"installed_version: NULL, {availability_summary}")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking pgcrypto extension: {str(e)}")
