#!/usr/bin/env python3
"""
YugabyteDB CIS Benchmark Tool
A comprehensive tool for auditing YugabyteDB clusters against CIS benchmarks.
"""

import argparse
import getpass
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from core.db_connector import YugabyteConnector
from core.models import BenchmarkReport, ControlStatus
from core.spec_loader import CISSpecificationLoader
from reports.console_reporter import ConsoleReporter
from reports.csv_reporter import CSVReporter
from reports.html_reporter import HTMLReporter
from reports.json_reporter import JSONReporter
from sections.access_control import AccessControlChecker
from sections.connection_login import ConnectionLoginChecker
from sections.directory_permissions import DirectoryPermissionsChecker
from sections.installation_patches import InstallationPatchesChecker
from sections.logging_monitoring import LoggingMonitoringChecker
from sections.special_configuration import SpecialConfigurationChecker
from sections.user_access import UserAccessChecker
from sections.yugabyte_settings import YugabyteSettingsChecker


class CISBenchmarkRunner:
    """Main CIS Benchmark runner that coordinates all sections"""

    def __init__(self, specs_directory: str, db_connector: YugabyteConnector, profile_level: str = "Level 1"):
        self.specs_directory = specs_directory
        self.db = db_connector
        self.profile_level = profile_level
        self.loader = CISSpecificationLoader(specs_directory)
        self.controls = []

        # Initialize section checkers in the correct order
        self.section_checkers = {
            'Installation and Patches': InstallationPatchesChecker(db_connector),
            'Directory and File Permissions': DirectoryPermissionsChecker(db_connector),
            'Logging Monitoring and Auditing': LoggingMonitoringChecker(db_connector),
            'User Access and Authorization': UserAccessChecker(db_connector),
            'Access Control and Password Policies': AccessControlChecker(db_connector),
            'Connection and Login': ConnectionLoginChecker(db_connector),
            'YugabyteDB Settings': YugabyteSettingsChecker(db_connector),
            'Special Configuration Considerations': SpecialConfigurationChecker(db_connector)
        }

    def run_benchmark(self, sections_filter=None) -> BenchmarkReport:
        """Run complete CIS benchmark"""
        # Load all controls
        try:
            self.controls = self.loader.load_all_specifications()
            logging.info(f"Loaded {len(self.controls)} total controls")
        except Exception as e:
            raise Exception(f"Failed to load controls: {e}")

        # Filter controls by profile level and sections
        filtered_controls = self._filter_controls(sections_filter)
        logging.info(f"Running {len(filtered_controls)} controls for {self.profile_level}")

        results = []
        passed = failed = warnings = skipped = 0

        for control in filtered_controls:
            try:
                result = self._execute_control_check(control)
                results.append(result)

                # Update counters
                if result.status == ControlStatus.PASS:
                    passed += 1
                elif result.status == ControlStatus.FAIL:
                    failed += 1
                elif result.status == ControlStatus.WARN:
                    warnings += 1
                elif result.status == ControlStatus.SKIP:
                    skipped += 1

                logging.info(f"Control {result.control_id}: {result.status.value} - {result.message[:100]}")

            except Exception as e:
                logging.error(f"Error executing control {control.control_id}: {e}")
                from core.models import ControlResult
                results.append(ControlResult(
                    control_id=control.control_id,
                    title=control.title,
                    status=ControlStatus.FAIL,
                    message=f"Control execution error: {str(e)}",
                    section=control.section
                ))
                failed += 1

        # Generate section summaries
        section_summaries = self._generate_section_summaries(results)

        return BenchmarkReport(
            cluster_info=self.db.get_cluster_info(),
            scan_time=datetime.now(),
            total_checks=len(filtered_controls),
            passed=passed,
            failed=failed,
            warnings=warnings,
            skipped=skipped,
            results=results,
            section_summaries=section_summaries,
            profile_level=self.profile_level
        )

    def _filter_controls(self, sections_filter=None):
        """Filter controls based on profile level and sections"""
        filtered = []
        for control in self.controls:
            if self._matches_profile(control):
                if sections_filter is None or any(section in control.section.lower().replace(' ', '_') for section in sections_filter):
                    filtered.append(control)
        return filtered

    def _matches_profile(self, control):
        """Check if control matches the current profile level"""
        if not control.profile_applicability:
            return True

        for profile in control.profile_applicability:
            profile_lower = profile.lower()
            target_lower = self.profile_level.lower()

            if profile_lower == target_lower:
                return True

            if target_lower in profile_lower:
                return True

            if "level 1" in target_lower and "level 2" in profile_lower:
                return True

        return False

    def _execute_control_check(self, control):
        """Execute a single control check using appropriate section checker"""
        if control.check_type.lower() == 'manual':
            from core.models import ControlResult
            return ControlResult(
                control_id=control.control_id,
                title=control.title,
                status=ControlStatus.SKIP,
                message="Manual control - requires manual verification",
                section=control.section,
                profile_level=control.profile_applicability[0] if control.profile_applicability else "",
                audit_command=control.audit
            )

        # Route to appropriate section checker
        section_name = control.section

        if section_name in self.section_checkers:
            checker = self.section_checkers[section_name]
            return checker.check_control(control)
        else:
            # Fallback for unknown sections
            from core.models import ControlResult
            return ControlResult(
                control_id=control.control_id,
                title=control.title,
                status=ControlStatus.SKIP,
                message="Unknown section - manual verification recommended",
                section=control.section,
                profile_level=control.profile_applicability[0] if control.profile_applicability else "",
                audit_command=control.audit
            )

    def _generate_section_summaries(self, results):
        """Generate summary statistics for each section"""
        from core.models import SectionSummary
        section_stats = {}

        for result in results:
            section = result.section
            if section not in section_stats:
                section_stats[section] = {
                    'total': 0, 'passed': 0, 'failed': 0, 'warnings': 0, 'skipped': 0
                }

            section_stats[section]['total'] += 1
            if result.status == ControlStatus.PASS:
                section_stats[section]['passed'] += 1
            elif result.status == ControlStatus.FAIL:
                section_stats[section]['failed'] += 1
            elif result.status == ControlStatus.WARN:
                section_stats[section]['warnings'] += 1
            elif result.status == ControlStatus.SKIP:
                section_stats[section]['skipped'] += 1

        summaries = []

        section_order = [
            'Installation and Patches',
            'Directory and File Permissions',
            'Logging Monitoring and Auditing',
            'User Access and Authorization',
            'Access Control and Password Policies',
            'Connection and Login',
            'YugabyteDB Settings',
            'Special Configuration Considerations'
        ]

        for section in section_order:
            if section in section_stats:
                stats = section_stats[section]
                pass_percentage = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
                summaries.append(SectionSummary(
                    section_name=section,
                    total_controls=stats['total'],
                    passed=stats['passed'],
                    failed=stats['failed'],
                    warnings=stats['warnings'],
                    skipped=stats['skipped'],
                    pass_percentage=pass_percentage
                ))

        return summaries


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='YugabyteDB CIS Benchmark Tool')
    parser.add_argument('--host', default='localhost', help='YugabyteDB host')
    parser.add_argument('--port', type=int, default=5433, help='YugabyteDB port')
    parser.add_argument('--database', default='yugabyte', help='Database name')
    parser.add_argument('--user', default='yugabyte', help='Database user')
    parser.add_argument('--password', help='Database password')
    parser.add_argument('--specs-dir', default='cis_specifications',
                        help='CIS specifications directory')
    parser.add_argument('--profile-level', choices=['Level 1', 'Level 2'],
                        default='Level 1', help='CIS profile level')
    parser.add_argument('--output-format', choices=['console', 'json', 'html', 'csv'],
                        default='console', help='Output format')
    parser.add_argument('--output-file', help='Output file (for json/html/csv formats)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        default='INFO', help='Logging level')
    parser.add_argument('--sections', nargs='+',
                        help='Specific sections to run (e.g., logging_monitoring_and_auditing)')

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Get password if not provided
    password = args.password
    if not password:
        password = getpass.getpass("Enter database password: ")

    # Create database connector
    db_connector = YugabyteConnector(
        host=args.host,
        port=args.port,
        database=args.database,
        user=args.user,
        password=password
    )

    # Test connection
    if not db_connector.connect():
        print("Failed to connect to YugabyteDB. Please check your connection parameters.")
        sys.exit(1)

    try:
        # Run benchmark
        runner = CISBenchmarkRunner(args.specs_dir, db_connector, args.profile_level)
        report = runner.run_benchmark(args.sections)

        # Generate output using appropriate reporter
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if args.output_format == 'console':
            ConsoleReporter.generate_report(report)
        elif args.output_format == 'json':
            output_file = args.output_file or f'yugabyte_cis_report_{timestamp}.json'
            JSONReporter.generate_report(report, output_file)
            print(f"JSON report generated: {output_file}")
        elif args.output_format == 'html':
            output_file = args.output_file or f'yugabyte_cis_report_{timestamp}.html'
            HTMLReporter.generate_report(report, output_file)
            print(f"HTML report generated: {output_file}")
        elif args.output_format == 'csv':
            output_file = args.output_file or f'yugabyte_cis_report_{timestamp}.csv'
            CSVReporter.generate_report(report, output_file)
            print(f"CSV report generated: {output_file}")
    except Exception as e:
        logging.error(f"Benchmark execution failed: {e}")
        sys.exit(1)

    finally:
        db_connector.close()


if __name__ == '__main__':
    main()
