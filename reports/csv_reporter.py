"""
CSV Report Generator for YugabyteDB CIS Benchmark Tool
"""

import csv

from core.models import BenchmarkReport


class CSVReporter:
    """Generate CSV format reports"""

    @staticmethod
    def generate_report(report: BenchmarkReport, output_file: str):
        """Generate CSV report and save to file"""
        CSVReporter._write_main_results_csv(report, output_file)

        # Generate additional CSV files
        base_name = output_file.rsplit('.', 1)[0]
        CSVReporter._write_summary_csv(report, f"{base_name}_summary.csv")
        CSVReporter._write_section_summary_csv(report, f"{base_name}_sections.csv")

    @staticmethod
    def _write_main_results_csv(report: BenchmarkReport, output_file: str):
        """Write main results to CSV"""
    @staticmethod
    def _write_main_results_csv(report: BenchmarkReport, output_file: str):
        """Write main results to CSV"""
        fieldnames = [
            'control_id', 'title', 'section', 'status', 'message',
            'profile_level', 'expected', 'actual', 'severity',
            'audit_command', 'remediation', 'impact'
        ]

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for result in report.results:
                writer.writerow({
                    'control_id': result.control_id,
                    'title': result.title,
                    'section': result.section,
                    'status': result.status.value,
                    'message': result.message,
                    'profile_level': result.profile_level,
                    'expected': result.expected or '',
                    'actual': result.actual or '',
                    'severity': result.severity,
                    'audit_command': result.audit_command or '',
                    'remediation': result.remediation or '',
                    'impact': result.impact or ''
                })

    @staticmethod
    def _write_summary_csv(report: BenchmarkReport, output_file: str):
        """Write summary information to CSV"""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)

            # Write header
            writer.writerow(['Metric', 'Value'])

            # Write cluster information
            writer.writerow(['Cluster Host', report.cluster_info.get('host', 'Unknown')])
            writer.writerow(['Cluster Port', report.cluster_info.get('port', 'Unknown')])
            writer.writerow(['Database', report.cluster_info.get('database', 'Unknown')])
            writer.writerow(['Version', report.cluster_info.get('version', 'Unknown')])
            writer.writerow(['Scan Time', report.scan_time.strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['Profile Level', report.profile_level])

            # Write summary statistics
            writer.writerow([])  # Empty row for separation
            writer.writerow(['Summary Statistics', ''])
            writer.writerow(['Total Checks', report.total_checks])
            writer.writerow(['Passed', report.passed])
            writer.writerow(['Failed', report.failed])
            writer.writerow(['Warnings', report.warnings])
            writer.writerow(['Skipped', report.skipped])
            writer.writerow(['Pass Rate (%)', f"{report.get_pass_rate():.1f}"])

    @staticmethod
    def _write_section_summary_csv(report: BenchmarkReport, output_file: str):
        """Write section summaries to CSV"""
        fieldnames = [
            'section_name', 'total_controls', 'passed', 'failed',
            'warnings', 'skipped', 'pass_percentage'
        ]

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for section in report.section_summaries:
                writer.writerow({
                    'section_name': section.section_name,
                    'total_controls': section.total_controls,
                    'passed': section.passed,
                    'failed': section.failed,
                    'warnings': section.warnings,
                    'skipped': section.skipped,
                    'pass_percentage': f"{section.pass_percentage:.1f}"
                })
