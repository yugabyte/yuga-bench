"""
YugabyteDB Database Connector
"""

import logging
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor


class YugabyteConnector:
    """Handles connections to YugabyteDB cluster"""

    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.connection = None
        self.cluster_info = {}

    def connect(self) -> bool:
        """Establish connection to YugabyteDB"""
        try:
            self.connection = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                cursor_factory=RealDictCursor,
                connect_timeout=10
            )
            self._gather_cluster_info()
            return True
        except Exception as e:
            logging.error(f"Failed to connect to YugabyteDB: {e}")
            return False

    def execute_query(self, query: str) -> Optional[List[Dict]]:
        """Execute a SQL query and return results"""
        if not self.connection:
            if not self.connect():
                return None

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query)
                return cursor.fetchall()
        except Exception as e:
            logging.error(f"Query execution failed: {e}")
            return None

    def get_setting(self, setting_name: str) -> Optional[str]:
        """Get a specific YugabyteDB setting value"""
        query = f"SHOW {setting_name};"
        result = self.execute_query(query)
        if result and len(result) > 0:
            return result[0].get(setting_name)
        return None

    def check_table_exists(self, table_name: str, schema: str = 'public') -> bool:
        """Check if a table exists"""
        query = """
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = %s AND table_name = %s
        );
        """
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, (schema, table_name))
                result = cursor.fetchone()
                return result['exists'] if result else False
        except Exception as e:
            logging.error(f"Error checking table existence: {e}")
            return False

    def get_database_size(self) -> Optional[str]:
        """Get database size"""
        query = f"SELECT pg_size_pretty(pg_database_size('{self.database}')) as size;"
        result = self.execute_query(query)
        if result and len(result) > 0:
            return result[0].get('size')
        return None

    def get_active_connections(self) -> Optional[int]:
        """Get number of active connections"""
        query = "SELECT count(*) as connections FROM pg_stat_activity WHERE state = 'active';"
        result = self.execute_query(query)
        if result and len(result) > 0:
            return result[0].get('connections')
        return None

    def _gather_cluster_info(self):
        """Gather comprehensive cluster information"""
        try:
            # Version information
            version_result = self.execute_query("SELECT version();")
            self.cluster_info['version'] = version_result[0]['version'] if version_result else "Unknown"

            # Current user and database
            user_result = self.execute_query("SELECT current_user, current_database();")
            if user_result:
                self.cluster_info['current_user'] = user_result[0]['current_user']
                self.cluster_info['current_database'] = user_result[0]['current_database']

            # Server settings
            self.cluster_info['data_directory'] = self.get_setting('data_directory') or "Unknown"
            self.cluster_info['config_file'] = self.get_setting('config_file') or "Unknown"
            self.cluster_info['log_directory'] = self.get_setting('log_directory') or "Unknown"

            # Additional cluster info
            self.cluster_info['database_size'] = self.get_database_size() or "Unknown"
            self.cluster_info['active_connections'] = self.get_active_connections() or 0

        except Exception as e:
            logging.warning(f"Could not gather complete cluster info: {e}")

    def get_cluster_info(self) -> Dict[str, Any]:
        """Get cluster information"""
        base_info = {
            'host': self.host,
            'port': self.port,
            'database': self.database,
            'scan_user': self.user
        }
        base_info.update(self.cluster_info)
        return base_info

    def test_connection(self) -> bool:
        """Test database connectivity"""
        try:
            test_result = self.execute_query("SELECT 1 as test;")
            return test_result is not None and len(test_result) > 0
        except Exception:
            return False

    def close(self):
        """Close the database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
