"""
CSV Report Generator for YugabyteDB CIS Benchmark Tool
"""

import csv
from datetime import datetime
from typing import List, Dict, Any
from core.models import BenchmarkReport, ControlStatus


class CSVReporter:
    """Generate CSV format reports with Manual controls support"""

    @staticmethod
    def generate_report(report: BenchmarkReport, output_file: str):
        """Generate CSV report and save to file"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            CSVReporter._write_csv_content(writer, report)

    @staticmethod
    def generate_summary_report(report: BenchmarkReport, output_file: str):
        """Generate summary CSV report"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            CSVReporter._write_summary_csv(writer, report)

    @staticmethod
    def generate_manual_controls_report(report: BenchmarkReport, output_file: str):
        """Generate CSV report specifically for manual controls"""
        manual_controls = [r for r in report.results if r.status == ControlStatus.MANUAL]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            CSVReporter._write_manual_controls_csv(writer, manual_controls, report)

    @staticmethod
    def _write_csv_content(writer: csv.writer, report: BenchmarkReport):
        """Write detailed CSV content"""
        # Write metadata header
        CSVReporter._write_metadata_section(writer, report)
        
        # Write summary section
        CSVReporter._write_summary_section(writer, report)
        
        # Write detailed results
        CSVReporter._write_detailed_results(writer, report)

    @staticmethod
    def _write_metadata_section(writer: csv.writer, report: BenchmarkReport):
        """Write metadata section"""
        writer.writerow(['=== YUGABYTEDB CIS BENCHMARK REPORT ==='])
        writer.writerow([])
        writer.writerow(['Report Metadata'])
        writer.writerow(['Profile Level', report.profile_level])
        writer.writerow(['Cluster Host', report.cluster_info.get('host', 'Unknown')])
        writer.writerow(['Cluster Port', report.cluster_info.get('port', 'Unknown')])
        writer.writerow(['Database', report.cluster_info.get('database', 'Unknown')])
        writer.writerow(['Version', report.cluster_info.get('version', 'Unknown')])
        writer.writerow(['Scan Time', report.scan_time.strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])

    @staticmethod
    def _write_summary_section(writer: csv.writer, report: BenchmarkReport):
        """Write summary section with Manual controls"""
        writer.writerow(['Summary Statistics'])
        writer.writerow(['Metric', 'Count', 'Percentage'])
        
        total = report.total_checks
        writer.writerow(['Total Checks', total, '100.0%'])
        writer.writerow(['Passed', report.passed, f'{(report.passed/total*100):.1f}%' if total > 0 else '0.0%'])
        writer.writerow(['Failed', report.failed, f'{(report.failed/total*100):.1f}%' if total > 0 else '0.0%'])
        writer.writerow(['Skipped', report.skipped, f'{(report.skipped/total*100):.1f}%' if total > 0 else '0.0%'])
        writer.writerow(['Manual', report.manual, f'{(report.manual/total*100):.1f}%' if total > 0 else '0.0%'])
        
        # Automated tests statistics
        automated_total = report.passed + report.failed + report.skipped
        automated_pass_rate = (report.passed / automated_total * 100) if automated_total > 0 else 0
        writer.writerow(['Automated Tests Total', automated_total, f'{(automated_total/total*100):.1f}%' if total > 0 else '0.0%'])
        writer.writerow(['Automated Pass Rate', report.passed, f'{automated_pass_rate:.1f}%'])
        
        writer.writerow([])

    @staticmethod
    def _write_detailed_results(writer: csv.writer, report: BenchmarkReport):
        """Write detailed results section"""
        writer.writerow(['Detailed Results'])
        
        # CSV Column Headers
        headers = [
            'Control ID',
            'Title', 
            'Status',
            'Section',
            'Profile Level',
            'Message',
            'Severity',
            'Expected',
            'Actual',
            'Audit Command',
            'Remediation',
            'Impact',
            'Manual Steps',
            'References'
        ]
        writer.writerow(headers)
        
        # Sort results by status priority and control ID
        sorted_results = sorted(
            report.results, 
            key=lambda x: (CSVReporter._get_status_priority(x.status), x.control_id)
        )
        
        for result in sorted_results:
            # Handle manual steps formatting
            manual_steps = ''
            if result.status == ControlStatus.MANUAL and result.manual_steps:
                manual_steps = ' | '.join(result.manual_steps)
            
            # Handle references formatting
            references = ''
            if hasattr(result, 'references') and result.references:
                references = ' | '.join(result.references)
            
            row = [
                result.control_id,
                result.title,
                result.status.value,
                result.section,
                result.profile_level,
                result.message,
                getattr(result, 'severity', 'MEDIUM'),
                result.expected or '',
                result.actual or '',
                result.audit_command or '',
                result.remediation or '',
                result.impact or '',
                manual_steps,
                references
            ]
            writer.writerow(row)

    @staticmethod
    def _write_summary_csv(writer: csv.writer, report: BenchmarkReport):
        """Write summary-only CSV"""
        writer.writerow(['YugabyteDB CIS Benchmark Summary Report'])
        writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])
        
        # Overall Summary
        writer.writerow(['Overall Summary'])
        writer.writerow(['Total Checks', report.total_checks])
        writer.writerow(['Passed', report.passed])
        writer.writerow(['Failed', report.failed])
        writer.writerow(['Skipped', report.skipped])
        writer.writerow(['Manual', report.manual])
        writer.writerow(['Automated Pass Rate', f'{report.pass_percentage:.1f}%'])
        writer.writerow([])
        
        # Section Summaries
        writer.writerow(['Section Summaries'])
        writer.writerow(['Section', 'Total', 'Passed', 'Failed', 'Skipped', 'Manual', 'Auto Pass Rate'])
        
        for section in report.section_summaries:
            automated_total = section.passed + section.failed + section.skipped
            auto_pass_rate = (section.passed / automated_total * 100) if automated_total > 0 else 0
            
            writer.writerow([
                section.section_name,
                section.total_controls,
                section.passed,
                section.failed,
                section.skipped,
                section.manual,
                f'{auto_pass_rate:.1f}%'
            ])

    @staticmethod
    def _write_manual_controls_csv(writer: csv.writer, manual_controls: List, report: BenchmarkReport):
        """Write CSV specifically for manual controls"""
        writer.writerow(['YugabyteDB CIS Benchmark - Manual Verification Controls'])
        writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(['Profile Level:', report.profile_level])
        writer.writerow([])
        
        writer.writerow([f'Total Manual Controls: {len(manual_controls)}'])
        writer.writerow(['Estimated Total Verification Time:', f'{len(manual_controls) * 10} minutes'])
        writer.writerow([])
        
        # Headers for manual controls
        headers = [
            'Control ID',
            'Title',
            'Section',
            'Profile Level',
            'Severity',
            'Verification Steps',
            'Expected Result',
            'Remediation',
            'Impact',
            'References',
            'Estimated Time',
            'Verification Status',
            'Verifier',
            'Verification Date',
            'Notes'
        ]
        writer.writerow(headers)
        
        for control in manual_controls:
            # Format verification steps
            steps = ' | '.join(control.manual_steps) if control.manual_steps else 'See CIS documentation'
            
            # Format references
            references = ' | '.join(control.references) if hasattr(control, 'references') and control.references else ''
            
            row = [
                control.control_id,
                control.title,
                control.section,
                control.profile_level,
                getattr(control, 'severity', 'MEDIUM'),
                steps,
                control.expected or 'Manual verification required',
                control.remediation or '',
                control.impact or '',
                references,
                '5-15 minutes',
                '',  # To be filled by verifier
                '',  # To be filled by verifier
                '',  # To be filled by verifier
                ''   # To be filled by verifier
            ]
            writer.writerow(row)
        
        writer.writerow([])
        writer.writerow(['Verification Instructions:'])
        writer.writerow(['1. Review each control and its verification steps'])
        writer.writerow(['2. Perform the manual verification as described'])
        writer.writerow(['3. Update Verification Status (PASS/FAIL/N/A)'])
        writer.writerow(['4. Record your name in Verifier column'])
        writer.writerow(['5. Record verification date'])
        writer.writerow(['6. Add any relevant notes'])

    @staticmethod
    def _get_status_priority(status: ControlStatus) -> int:
        """Get priority for status sorting"""
        priority_map = {
            ControlStatus.FAIL: 1,
            ControlStatus.MANUAL: 2,
            ControlStatus.SKIP: 3,
            ControlStatus.INFO: 4,
            ControlStatus.PASS: 5
        }
        return priority_map.get(status, 999)

    @staticmethod
    def generate_compliance_csv(report: BenchmarkReport, output_file: str):
        """Generate compliance-focused CSV report"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            writer.writerow(['YugabyteDB CIS Benchmark - Compliance Report'])
            writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow([])
            
            # Compliance status overview
            writer.writerow(['Compliance Status Overview'])
            writer.writerow(['Framework', 'Version', 'Total Controls', 'Compliant', 'Non-Compliant', 'Manual Review', 'Compliance %'])
            
            automated_total = report.passed + report.failed + report.skipped
            compliance_rate = (report.passed / automated_total * 100) if automated_total > 0 else 0
            
            writer.writerow([
                'CIS Benchmark',
                '1.0.0',
                report.total_checks,
                report.passed,
                report.failed + report.skipped,  # Non-compliant includes skipped
                report.manual,
                f'{compliance_rate:.1f}%'
            ])
            writer.writerow([])
            
            # Gap analysis
            writer.writerow(['Compliance Gaps (Failed Controls)'])
            writer.writerow(['Priority', 'Control ID', 'Title', 'Section', 'Severity', 'Remediation Required'])
            
            failed_controls = [r for r in report.results if r.status == ControlStatus.FAIL]
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            failed_controls.sort(key=lambda x: severity_order.get(getattr(x, 'severity', 'MEDIUM'), 99))
            
            for i, control in enumerate(failed_controls, 1):
                priority = 'IMMEDIATE' if getattr(control, 'severity', 'MEDIUM') in ['CRITICAL', 'HIGH'] else 'HIGH'
                writer.writerow([
                    priority,
                    control.control_id,
                    control.title,
                    control.section,
                    getattr(control, 'severity', 'MEDIUM'),
                    'Yes' if control.remediation else 'See documentation'
                ])
            
            writer.writerow([])
            
            # Manual verification requirements
            writer.writerow(['Manual Verification Requirements'])
            writer.writerow(['Control ID', 'Title', 'Section', 'Severity', 'Review Priority', 'Est. Time'])
            
            manual_controls = [r for r in report.results if r.status == ControlStatus.MANUAL]
            manual_controls.sort(key=lambda x: severity_order.get(getattr(x, 'severity', 'MEDIUM'), 99))
            
            for control in manual_controls:
                severity = getattr(control, 'severity', 'MEDIUM')
                priority = 'HIGH' if severity in ['CRITICAL', 'HIGH'] else 'MEDIUM'
                
                writer.writerow([
                    control.control_id,
                    control.title,
                    control.section,
                    severity,
                    priority,
                    '10-15 min'
                ])

    @staticmethod
    def generate_action_plan_csv(report: BenchmarkReport, output_file: str):
        """Generate action plan CSV for remediation"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            writer.writerow(['YugabyteDB CIS Benchmark - Action Plan'])
            writer.writerow(['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow([])
            
            headers = [
                'Priority',
                'Control ID',
                'Title',
                'Section',
                'Current Status',
                'Required Action',
                'Remediation Steps',
                'Impact Level',
                'Estimated Effort',
                'Target Date',
                'Assigned To',
                'Status',
                'Notes'
            ]
            writer.writerow(headers)
            
            # Process failed controls first (highest priority)
            failed_controls = [r for r in report.results if r.status == ControlStatus.FAIL]
            manual_controls = [r for r in report.results if r.status == ControlStatus.MANUAL]
            
            all_action_items = []
            
            # Add failed controls
            for control in failed_controls:
                severity = getattr(control, 'severity', 'MEDIUM')
                priority = 'P1 - CRITICAL' if severity == 'CRITICAL' else 'P2 - HIGH' if severity == 'HIGH' else 'P3 - MEDIUM'
                effort = 'High' if severity in ['CRITICAL', 'HIGH'] else 'Medium'
                
                all_action_items.append([
                    priority,
                    control.control_id,
                    control.title,
                    control.section,
                    'FAILED',
                    'Implement Security Control',
                    control.remediation or 'See CIS benchmark documentation',
                    control.impact or 'Security risk',
                    effort,
                    '',  # To be filled
                    '',  # To be filled
                    'Open',
                    ''   # To be filled
                ])
            
            # Add high-priority manual controls
            for control in manual_controls:
                severity = getattr(control, 'severity', 'MEDIUM')
                if severity in ['CRITICAL', 'HIGH']:
                    priority = 'P2 - HIGH' if severity == 'CRITICAL' else 'P3 - MEDIUM'
                    
                    all_action_items.append([
                        priority,
                        control.control_id,
                        control.title,
                        control.section,
                        'MANUAL REVIEW REQUIRED',
                        'Complete Manual Verification',
                        ' | '.join(control.manual_steps) if control.manual_steps else 'Perform manual review',
                        control.impact or 'Compliance verification',
                        'Low',
                        '',  # To be filled
                        '',  # To be filled
                        'Open',
                        ''   # To be filled
                    ])
            
            # Sort by priority
            priority_order = {'P1 - CRITICAL': 0, 'P2 - HIGH': 1, 'P3 - MEDIUM': 2, 'P4 - LOW': 3}
            all_action_items.sort(key=lambda x: priority_order.get(x[0], 99))
            
            for item in all_action_items:
                writer.writerow(item)
