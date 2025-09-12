"""
User Access and Authorization section checker for YugabyteDB CIS Benchmark
"""

import logging

from core.base_checker import BaseChecker
from core.models import CISControl, ControlResult


class UserAccessChecker(BaseChecker):
    """Checker for User Access and Authorization section controls"""

    def check_control(self, control: CISControl) -> ControlResult:
        """Route control check to appropriate method"""
        control_id = control.control_id

        try:
            if control_id.startswith("4.1"):
                return self._check_superuser_accounts(control)
            elif control_id.startswith("4.2"):
                return self._check_user_privileges(control)
            elif control_id.startswith("4.3"):
                return self._check_role_management(control)
            elif control_id.startswith("4.4"):
                return self._check_user_authentication(control)
            else:
                return self._check_generic_user_access(control)
        except Exception as e:
            return self._create_fail_result(control, f"Error during user access check: {str(e)}")

    def _check_superuser_accounts(self, control: CISControl) -> ControlResult:
        """Check superuser account configurations"""
        try:
            # Get list of superusers
            superuser_query = "SELECT rolname FROM pg_roles WHERE rolsuper = true;"
            superusers = self.db.execute_query(superuser_query)

            if not superusers:
                return self._create_fail_result(control, "Could not retrieve superuser information")

            superuser_names = [user['rolname'] for user in superusers]

            # Check for default superuser accounts that should be secured
            default_superusers = ['postgres', 'yugabyte']
            found_defaults = [name for name in superuser_names if name in default_superusers]

            if len(superuser_names) == 0:
                return self._create_fail_result(control, "No superuser accounts found")
            elif len(superuser_names) > 3:
                return self._create_warn_result(control,
                                                f"Many superuser accounts found: {', '.join(superuser_names)}",
                                                expected="Limited number of superusers",
                                                actual=f"{len(superuser_names)} superusers")
            else:
                return self._create_pass_result(control,
                                                f"Reasonable number of superuser accounts: {', '.join(superuser_names)}",
                                                expected="Limited number of superusers",
                                                actual=f"{len(superuser_names)} superusers")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking superuser accounts: {str(e)}")

    def _check_user_privileges(self, control: CISControl) -> ControlResult:
        """Check user privilege assignments"""
        try:
            # Get users with various dangerous privileges
            dangerous_privs_query = """
            SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication
            FROM pg_roles
            WHERE rolcanlogin = true;
            """

            users = self.db.execute_query(dangerous_privs_query)
            if not users:
                return self._create_fail_result(control, "Could not retrieve user privilege information")

            issues = []
            for user in users:
                user_name = user['rolname']
                if user['rolsuper']:
                    continue  # Skip superusers for this check

                dangerous_privs = []
                if user['rolcreaterole']:
                    dangerous_privs.append('CREATEROLE')
                if user['rolcreatedb']:
                    dangerous_privs.append('CREATEDB')
                if user['rolreplication']:
                    dangerous_privs.append('REPLICATION')

                if dangerous_privs:
                    issues.append(f"{user_name}: {', '.join(dangerous_privs)}")

            if issues:
                return self._create_warn_result(control,
                                                f"Users with elevated privileges: {'; '.join(issues)}",
                                                expected="Minimal privileges for non-superusers",
                                                actual=f"{len(issues)} users with elevated privileges")
            else:
                return self._create_pass_result(control,
                                                "No non-superuser accounts have dangerous privileges",
                                                expected="Minimal privileges for non-superusers",
                                                actual="All non-superusers have appropriate privileges")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking user privileges: {str(e)}")

    def _check_role_management(self, control: CISControl) -> ControlResult:
        """Check role management practices"""
        try:
            # Count total roles vs users
            roles_query = "SELECT count(*) as role_count FROM pg_roles WHERE NOT rolcanlogin;"
            users_query = "SELECT count(*) as user_count FROM pg_roles WHERE rolcanlogin;"

            roles_result = self.db.execute_query(roles_query)
            users_result = self.db.execute_query(users_query)

            if not roles_result or not users_result:
                return self._create_fail_result(control, "Could not retrieve role/user counts")

            role_count = roles_result[0]['role_count']
            user_count = users_result[0]['user_count']

            # Check if roles are being used for privilege management
            if role_count == 0:
                return self._create_warn_result(control,
                                                "No roles defined - consider using roles for privilege management",
                                                expected="Use of roles for privilege management",
                                                actual=f"{role_count} roles, {user_count} users")
            else:
                return self._create_pass_result(control,
                                                f"Roles are being used for privilege management: {role_count} roles, {user_count} users",
                                                expected="Use of roles for privilege management",
                                                actual=f"{role_count} roles, {user_count} users")

        except Exception as e:
            return self._create_fail_result(control, f"Error checking role management: {str(e)}")

    def _check_user_authentication(self, control: CISControl) -> ControlResult:
        """Check user authentication settings"""
        try:
            # Check password encryption setting
            password_encryption = self.db.get_setting('password_encryption')

            if not password_encryption:
                return self._create_fail_result(control, "Could not retrieve password encryption setting")

            secure_methods = ['scram-sha-256', 'md5']

            if password_encryption in secure_methods:
                return self._create_pass_result(control,
                                                f"Password encryption is properly configured: {password_encryption}",
                                                expected="Secure password encryption",
                                                actual=password_encryption)
            else:
                return self._create_fail_result(control,
                                                f"Insecure password encryption method: {password_encryption}",
                                                expected="scram-sha-256 or md5",
                                                actual=password_encryption)

        except Exception as e:
            return self._create_fail_result(control, f"Error checking user authentication: {str(e)}")

    def _check_generic_user_access(self, control: CISControl) -> ControlResult:
        """Generic user access control check"""
        # Try to extract setting name from audit command
        setting_name = self._extract_setting_name_from_audit(control.audit)

        if setting_name:
            setting_value = self.db.get_setting(setting_name)
            return self._create_info_result(control,
                                            f"User access setting {setting_name}: {setting_value}",
                                            actual=str(setting_value))
        else:
            return self._create_skip_result(control, "Generic user access check - manual verification required")
