"""
Connection and Login section checker for YugabyteDB CIS Benchmark
"""

import logging

from core.base_checker import BaseChecker
from core.models import CISControl, ControlResult


class ConnectionLoginChecker(BaseChecker):
    """Checker for Connection and Login section controls"""

    def check_control(self, control: CISControl) -> ControlResult:
        """Route control check to appropriate method"""
        control_id = control.control_id

        try:
            if control_id.startswith("6.1"):
                return self._check_ssl_configuration(control)
            elif control_id.startswith("6.2"):
                return self._check_connection_limits(control)
            elif control_id.startswith("6.3"):
                return self._check_network_security(control)
            elif control_id.startswith("6.4"):
                return self._check_authentication_methods(control)
            else:
                return self._check_generic_connection_setting(control)
        except Exception as e:
            return self._create_fail_result(control, f"Error during connection/login check: {str(e)}")

    def _check_ssl_configuration(self, control: CISControl) -> ControlResult:
        """Check SSL/TLS configuration"""
        try:
            if "ssl" in control.audit.lower():
                ssl_setting = self.db.get_setting('ssl')

                if ssl_setting == 'on':
                    # Check for additional SSL settings
                    ssl_cert_file = self.db.get_setting('ssl_cert_file')
                    ssl_key_file = self.db.get_setting('ssl_key_file')
                    ssl_ca_file = self.db.get_setting('ssl_ca_file')

                    ssl_details = []
                    if ssl_cert_file:
                        ssl_details.append(f"cert: {ssl_cert_file}")
                    if ssl_key_file:
                        ssl_details.append(f"key: {ssl_key_file}")
                    if ssl_ca_file:
                        ssl_details.append(f"ca: {ssl_ca_file}")

                    details_str = f" ({', '.join(ssl_details)})" if ssl_details else ""

                    return self._create_pass_result(control,
                                                    f"SSL is enabled{details_str}",
                                                    expected="SSL enabled",
                                                    actual=f"SSL: {ssl_setting}{details_str}")
                else:
                    return self._create_fail_result(control,
                                                    f"SSL is not enabled: {ssl_setting}",
                                                    expected="SSL enabled",
                                                    actual=f"SSL: {ssl_setting}")
            else:
                return self._check_generic_connection_setting(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking SSL configuration: {str(e)}")

    def _check_connection_limits(self, control: CISControl) -> ControlResult:
        """Check connection limit configurations"""
        try:
            if "max_connections" in control.audit.lower():
                return self._check_max_connections(control)
            elif "superuser_reserved_connections" in control.audit.lower():
                return self._check_superuser_reserved_connections(control)
            else:
                return self._check_generic_connection_setting(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking connection limits: {str(e)}")

    def _check_max_connections(self, control: CISControl) -> ControlResult:
        """Check max_connections setting"""
        max_connections = self.db.get_setting('max_connections')

        if not max_connections:
            return self._create_fail_result(control, "Could not retrieve max_connections setting")

        try:
            max_conn_int = int(max_connections)

            if max_conn_int < 10:
                return self._create_warn_result(control,
                                                f"Very low max_connections setting: {max_connections}",
                                                expected="Reasonable connection limit (≥10)",
                                                actual=max_connections)
            elif max_conn_int > 1000:
                return self._create_warn_result(control,
                                                f"Very high max_connections setting: {max_connections} - may impact performance",
                                                expected="Reasonable connection limit (≤1000)",
                                                actual=max_connections)
            else:
                return self._create_pass_result(control,
                                                f"Reasonable max_connections setting: {max_connections}",
                                                expected="Reasonable connection limit",
                                                actual=max_connections)
        except (ValueError, TypeError):
            return self._create_fail_result(control, f"Invalid max_connections value: {max_connections}")

    def _check_superuser_reserved_connections(self, control: CISControl) -> ControlResult:
        """Check superuser_reserved_connections setting"""
        reserved_connections = self.db.get_setting('superuser_reserved_connections')

        if not reserved_connections:
            return self._create_fail_result(control, "Could not retrieve superuser_reserved_connections setting")

        try:
            reserved_int = int(reserved_connections)

            if reserved_int < 3:
                return self._create_fail_result(control,
                                                f"Insufficient superuser reserved connections: {reserved_connections} (should be ≥3)",
                                                expected="≥3 reserved connections",
                                                actual=reserved_connections)
            else:
                return self._create_pass_result(control,
                                                f"Adequate superuser reserved connections: {reserved_connections}",
                                                expected="≥3 reserved connections",
                                                actual=reserved_connections)
        except (ValueError, TypeError):
            return self._create_fail_result(control, f"Invalid superuser_reserved_connections value: {reserved_connections}")

    def _check_network_security(self, control: CISControl) -> ControlResult:
        """Check network security settings"""
        try:
            if "listen_addresses" in control.audit.lower():
                return self._check_listen_addresses(control)
            elif "port" in control.audit.lower():
                return self._check_port_configuration(control)
            else:
                return self._check_generic_connection_setting(control)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking network security: {str(e)}")

    def _check_listen_addresses(self, control: CISControl) -> ControlResult:
        """Check listen_addresses setting for security"""
        listen_addresses = self.db.get_setting('listen_addresses')

        if not listen_addresses:
            return self._create_fail_result(control, "Could not retrieve listen_addresses setting")

        addresses = [addr.strip() for addr in listen_addresses.split(',')]

        # Check for insecure configurations
        if '*' in addresses or '0.0.0.0' in addresses:
            return self._create_warn_result(control,
                                            f"Database listening on all addresses: {listen_addresses}",
                                            expected="Specific IP addresses",
                                            actual=listen_addresses)
        elif 'localhost' in addresses or '127.0.0.1' in addresses:
            if len(addresses) == 1:
                return self._create_pass_result(control,
                                                "Database listening only on localhost (secure for single-machine setup)",
                                                expected="Restricted listen addresses",
                                                actual=listen_addresses)
            else:
                return self._create_info_result(control,
                                                f"Database listening on multiple addresses including localhost: {listen_addresses}",
                                                actual=listen_addresses)
        else:
            return self._create_pass_result(control,
                                            f"Database listening on specific addresses: {listen_addresses}",
                                            expected="Specific IP addresses",
                                            actual=listen_addresses)

    def _check_port_configuration(self, control: CISControl) -> ControlResult:
        """Check port configuration"""
        port = self.db.get_setting('port')

        if not port:
            return self._create_fail_result(control, "Could not retrieve port setting")

        try:
            port_int = int(port)

            # Check if using default port
            if port_int == 5432 or port_int == 5433:
                return self._create_info_result(control,
                                                f"Using default PostgreSQL/YugabyteDB port: {port}",
                                                expected="Consider non-default port for security",
                                                actual=port)
            else:
                return self._create_pass_result(control,
                                                f"Using non-default port: {port}",
                                                expected="Non-default port",
                                                actual=port)
        except (ValueError, TypeError):
            return self._create_fail_result(control, f"Invalid port value: {port}")

    def _check_authentication_methods(self, control: CISControl) -> ControlResult:
        """Check authentication method configurations"""
        try:
            # This would typically involve checking pg_hba.conf
            # Since we can't directly access that file, we'll check related settings

            if "password_encryption" in control.audit.lower():
                return self._check_password_encryption_method(control)
            else:
                return self._create_skip_result(control,
                                                "Authentication methods require manual verification of pg_hba.conf")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking authentication methods: {str(e)}")

    def _check_password_encryption_method(self, control: CISControl) -> ControlResult:
        """Check password encryption method"""
        password_encryption = self.db.get_setting('password_encryption')

        if not password_encryption:
            return self._create_fail_result(control, "Could not retrieve password_encryption setting")

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
                                            f"Weak or unknown password encryption method: {password_encryption}",
                                            expected="scram-sha-256",
                                            actual=password_encryption)

    def _check_generic_connection_setting(self, control: CISControl) -> ControlResult:
        """Generic connection setting check"""
        setting_name = self._extract_setting_name_from_audit(control.audit)

        if setting_name:
            setting_value = self.db.get_setting(setting_name)
            return self._create_info_result(control,
                                            f"Connection setting {setting_name}: {setting_value}",
                                            actual=str(setting_value))
        else:
            return self._create_skip_result(control, "Generic connection setting check - manual verification required")
