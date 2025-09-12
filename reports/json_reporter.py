"""
JSON Report Generator for YugabyteDB CIS Benchmark Tool
"""

import json
from datetime import datetime

from core.models import BenchmarkReport


class JSONReporter:
    """Generate JSON format reports"""

    @staticmethod
    def generate_report(report: BenchmarkReport, output_file: str):
        """Generate JSON report and save to file"""
        report_data = JSONReporter._prepare_report_data(report)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

    @staticmethod
    def _prepare_report_data(report: BenchmarkReport) -> dict:
        """Prepare report data for JSON serialization"""
        return {
            "metadata": {
                "report_type": "YugabyteDB CIS Benchmark",
                "profile_level": report.profile_level,
                "generated_at": report.scan_time.isoformat(),
                "version": "1.0",
                "tool": "YugabyteDB CIS Benchmark Tool"
            },
            "cluster_info": report.cluster_info,
            "summary": {
                "total_checks": report.total_checks,
                "passed": report.passed,
                "failed": report.failed,
                "warnings": report.warnings,
                "skipped": report.skipped,
                "pass_rate": report.get_pass_rate()
            },
            "section_summaries": [summary.to_dict() for summary in report.section_summaries],
            "results": [result.to_dict() for result in report.results],
            "statistics": JSONReporter._generate_statistics(report)
        }

    @staticmethod
    def _generate_statistics(report: BenchmarkReport) -> dict:
        """Generate additional statistics"""
        results_by_status = {}
        results_by_section = {}

        # Count by status
        for result in report.results:
            status = result.status.value
            results_by_status[status] = results_by_status.get(status, 0) + 1

            # Count by section
            section = result.section
            if section not in results_by_section:
                results_by_section[section] = {
                    "total": 0, "passed": 0, "failed": 0, "warnings": 0, "skipped": 0, "info": 0
                }

            results_by_section[section]["total"] += 1
            if result.status.value == "PASS":
                results_by_section[section]["passed"] += 1
            elif result.status.value == "FAIL":
                results_by_section[section]["failed"] += 1
            elif result.status.value == "WARN":
                results_by_section[section]["warnings"] += 1
            elif result.status.value == "SKIP":
                results_by_section[section]["skipped"] += 1
            elif result.status.value == "INFO":
                results_by_section[section]["info"] += 1

        return {
            "results_by_status": results_by_status,
            "results_by_section": results_by_section,
            "compliance_score": report.get_pass_rate(),
            "risk_level": JSONReporter._calculate_risk_level(report)
        }

    @staticmethod
    def _calculate_risk_level(report: BenchmarkReport) -> str:
        """Calculate overall risk level based on results"""
        if report.total_checks == 0:
            return "Unknown"

        fail_rate = (report.failed / report.total_checks) * 100

        if fail_rate == 0:
            return "Low"
        elif fail_rate < 10:
            return "Medium"
        elif fail_rate < 25:
            return "High"
        else:
            return "Critical"
