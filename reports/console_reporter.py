"""
Console Report Generator for YugabyteDB CIS Benchmark Tool
"""

from core.models import BenchmarkReport, ControlStatus


class ConsoleReporter:
    """Generate console output reports"""

    @staticmethod
    def generate_report(report: BenchmarkReport):
        """Generate and print console report"""
        ConsoleReporter._print_header(report)
        ConsoleReporter._print_summary(report)
        ConsoleReporter._print_section_summaries(report)
        ConsoleReporter._print_failed_controls(report)
        ConsoleReporter._print_recommendations(report)

    @staticmethod
    def _print_header(report: BenchmarkReport):
        """Print report header"""
        print("=" * 80)
        print(f"YugabyteDB CIS Benchmark Report - {report.profile_level}")
        print("=" * 80)
        print(f"Cluster: {report.cluster_info.get('host')}:{report.cluster_info.get('port')}")
        print(f"Database: {report.cluster_info.get('database')}")
        print(f"Version: {report.cluster_info.get('version', 'Unknown')}")
        print(f"Scan Time: {report.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print()

    @staticmethod
    def _print_summary(report: BenchmarkReport):
        """Print overall summary"""
        print("Overall Summary:")
        print(f"  Total Checks: {report.total_checks}")

        if report.total_checks > 0:
            pass_rate = (report.passed / report.total_checks) * 100
            print(f"  Passed: {report.passed} ({pass_rate:.1f}%)")
            print(f"  Failed: {report.failed} ({(report.failed/report.total_checks)*100:.1f}%)")
        else:
            print(f"  Passed: {report.passed}")
            print(f"  Failed: {report.failed}")

        print(f"  Warnings: {report.warnings}")
        print(f"  Skipped: {report.skipped}")
        print()

    @staticmethod
    def _print_section_summaries(report: BenchmarkReport):
        """Print section summaries"""
        print("Section Summary:")
        print("-" * 80)

        for section in report.section_summaries:
            print(f"{section.section_name}:")
            print(f"  Controls: {section.total_controls} | "
                  f"Passed: {section.passed} | "
                  f"Failed: {section.failed} | "
                  f"Warnings: {section.warnings} | "
                  f"Pass Rate: {section.pass_percentage:.1f}%")
        print()

    @staticmethod
    def _print_failed_controls(report: BenchmarkReport):
        """Print details of failed controls"""
        failed_controls = [r for r in report.results if r.status == ControlStatus.FAIL]

        if not failed_controls:
            print("✓ No failed controls found!")
            print()
            return

        print(f"Failed Controls ({len(failed_controls)}):")
        print("-" * 80)

        for result in failed_controls:
            print(f"[FAIL] {result.control_id}: {result.title}")
            print(f"  Section: {result.section}")
            print(f"  Message: {result.message}")

            if result.expected and result.actual:
                print(f"  Expected: {result.expected}")
                print(f"  Actual: {result.actual}")

            if result.remediation:
                print(f"  Remediation: {result.remediation}")

            print()

    @staticmethod
    def _print_recommendations(report: BenchmarkReport):
        """Print recommendations based on results"""
        failed_count = report.failed
        warning_count = report.warnings

        print("Recommendations:")
        print("-" * 80)

        if failed_count == 0 and warning_count == 0:
            print("✓ Excellent! Your YugabyteDB configuration meets all CIS benchmark requirements.")
        elif failed_count == 0 and warning_count > 0:
            print(f"✓ Good! No critical failures found, but {warning_count} warnings need attention.")
            print("  Review warning items to further improve security posture.")
        else:
            print(f"⚠ Action Required: {failed_count} critical issues found.")
            print("  Priority actions:")
            print("  1. Address all FAILED controls immediately")
            print("  2. Review and resolve WARNING items")
            print("  3. Ensure manual controls are properly verified")

        # Section-specific recommendations
        high_risk_sections = [s for s in report.section_summaries if s.failed > 0]
        if high_risk_sections:
            print("\n  Focus areas:")
            for section in high_risk_sections:
                print(f"  - {section.section_name}: {section.failed} failed control(s)")

        print()
        print("For detailed remediation steps, review the failed controls above.")
        print("Consider implementing automated configuration management for ongoing compliance.")
