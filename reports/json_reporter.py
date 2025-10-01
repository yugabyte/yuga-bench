"""
JSON Report Generator for YugabyteDB CIS Benchmark Tool
"""

import json
from datetime import datetime
from typing import Dict, Any, List
from core.models import BenchmarkReport, ControlStatus


class JSONReporter:
    """Generate JSON format reports with Manual controls support"""

    @staticmethod
    def generate_report(report: BenchmarkReport, output_file: str):
        """Generate JSON report and save to file"""
        json_data = JSONReporter._generate_json_data(report)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False, default=JSONReporter._json_serializer)

    @staticmethod
    def _json_serializer(obj):
        """Custom JSON serializer for datetime and enum objects"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, ControlStatus):
            return obj.value
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    @staticmethod
    def _generate_json_data(report: BenchmarkReport) -> Dict[str, Any]:
        """Generate complete JSON data structure"""
        return {
            "metadata": JSONReporter._generate_metadata(report),
            "summary": JSONReporter._generate_summary(report),
            "section_summaries": JSONReporter._generate_section_summaries(report),
            "controls": JSONReporter._generate_controls_data(report),
            "compliance": JSONReporter._generate_compliance_data(report),
            "recommendations": JSONReporter._generate_recommendations(report)
        }

    @staticmethod
    def _generate_metadata(report: BenchmarkReport) -> Dict[str, Any]:
        """Generate metadata section"""
        return {
            "report_type": "YugabyteDB CIS Benchmark",
            "version": "1.0.0",
            "profile_level": report.profile_level,
            "scan_time": report.scan_time,
            "cluster_info": report.cluster_info,
            "total_execution_time": JSONReporter._calculate_execution_time(report),
            "report_format_version": "2.0",
            "supports_manual_controls": True
        }

    @staticmethod
    def _calculate_execution_time(report: BenchmarkReport) -> str:
        """Calculate estimated execution time"""
        # This would be calculated during actual execution
        # For now, return a placeholder
        return "< 1 minute"

    @staticmethod
    def _generate_summary(report: BenchmarkReport) -> Dict[str, Any]:
        """Generate summary statistics with Manual controls"""
        automated_total = report.passed + report.failed + report.skipped
        
        return {
            "total_checks": report.total_checks,
            "passed": report.passed,
            "failed": report.failed,
            "skipped": report.skipped,
            "manual": report.manual,
            "info": sum(1 for r in report.results if r.status == ControlStatus.INFO),
            "pass_percentage": round(report.pass_percentage, 2),
            "automated_checks": automated_total,
            "automated_pass_percentage": round((report.passed / automated_total * 100) if automated_total > 0 else 0, 2),
            "critical_failures": JSONReporter._count_critical_failures(report),
            "high_priority_manual": JSONReporter._count_high_priority_manual(report),
            "status_distribution": {
                "PASS": report.passed,
                "FAIL": report.failed,
                "SKIP": report.skipped,
                "MANUAL": report.manual,
                "INFO": sum(1 for r in report.results if r.status == ControlStatus.INFO)
            }
        }

    @staticmethod
    def _count_critical_failures(report: BenchmarkReport) -> int:
        """Count critical/high severity failures"""
        return sum(1 for r in report.results 
                  if r.status == ControlStatus.FAIL and 
                  getattr(r, 'severity', 'MEDIUM') in ['CRITICAL', 'HIGH'])

    @staticmethod
    def _count_high_priority_manual(report: BenchmarkReport) -> int:
        """Count high priority manual controls"""
        return sum(1 for r in report.results 
                  if r.status == ControlStatus.MANUAL and 
                  getattr(r, 'severity', 'MEDIUM') in ['CRITICAL', 'HIGH'])

    @staticmethod
    def _generate_section_summaries(report: BenchmarkReport) -> List[Dict[str, Any]]:
        """Generate section summaries with Manual controls"""
        summaries = []
        
        for section in report.section_summaries:
            automated_total = section.passed + section.failed + section.skipped
            
            summary = {
                "section_name": section.section_name,
                "total_controls": section.total_controls,
                "passed": section.passed,
                "failed": section.failed,
                "skipped": section.skipped,
                "manual": section.manual,
                "pass_percentage": round(section.pass_percentage, 2),
                "automated_total": automated_total,
                "automated_pass_percentage": round((section.passed / automated_total * 100) if automated_total > 0 else 0, 2),
                "risk_level": JSONReporter._calculate_section_risk_level(section),
                "priority_controls": JSONReporter._get_section_priority_controls(report, section.section_name)
            }
            summaries.append(summary)
        
        return summaries

    @staticmethod
    def _calculate_section_risk_level(section) -> str:
        """Calculate risk level for a section"""
        fail_rate = (section.failed / (section.passed + section.failed)) * 100 if (section.passed + section.failed) > 0 else 0
        
        if fail_rate >= 50:
            return "HIGH"
        elif fail_rate >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def _get_section_priority_controls(report: BenchmarkReport, section_name: str) -> List[str]:
        """Get priority controls for a section (failed + high priority manual)"""
        priority_controls = []
        
        for result in report.results:
            if result.section == section_name:
                if result.status == ControlStatus.FAIL:
                    priority_controls.append(result.control_id)
                elif (result.status == ControlStatus.MANUAL and 
                      getattr(result, 'severity', 'MEDIUM') in ['CRITICAL', 'HIGH']):
                    priority_controls.append(result.control_id)
        
        return priority_controls[:5]  # Return top 5 priority controls

    @staticmethod
    def _generate_controls_data(report: BenchmarkReport) -> List[Dict[str, Any]]:
        """Generate detailed controls data"""
        controls = []
        
        for result in report.results:
            control_data = {
                "control_id": result.control_id,
                "title": result.title,
                "status": result.status,
                "message": result.message,
                "profile_level": result.profile_level,
                "section": result.section,
                "severity": getattr(result, 'severity', 'MEDIUM'),
                "timestamp": datetime.now()  # Would be actual execution timestamp
            }
            
            # Add optional fields if present
            if result.expected:
                control_data["expected"] = result.expected
            if result.actual:
                control_data["actual"] = result.actual
            if result.audit_command:
                control_data["audit_command"] = result.audit_command
            if result.remediation:
                control_data["remediation"] = result.remediation
            if result.impact:
                control_data["impact"] = result.impact
            if result.references:
                control_data["references"] = result.references
            
            # Add Manual control specific fields
            if result.status == ControlStatus.MANUAL:
                control_data["manual_verification"] = {
                    "required": True,
                    "steps": result.manual_steps or [],
                    "verification_method": "manual_review",
                    "estimated_time": "5-15 minutes",
                    "requires_admin_access": True
                }
            
            # Add compliance framework mappings if available
            if hasattr(result, 'compliance_frameworks') and result.compliance_frameworks:
                control_data["compliance_frameworks"] = result.compliance_frameworks
            
            controls.append(control_data)
        
        return controls

    @staticmethod
    def _generate_compliance_data(report: BenchmarkReport) -> Dict[str, Any]:
        """Generate compliance framework data"""
        compliance_data = {
            "frameworks": {
                "CIS": {
                    "version": "1.0.0",
                    "applicable_controls": report.total_checks,
                    "compliant_controls": report.passed,
                    "non_compliant_controls": report.failed,
                    "manual_verification_required": report.manual,
                    "compliance_percentage": round(report.pass_percentage, 2)
                }
            },
            "compliance_gaps": JSONReporter._identify_compliance_gaps(report),
            "manual_verification_requirements": JSONReporter._get_manual_verification_summary(report)
        }
        
        return compliance_data

    @staticmethod
    def _identify_compliance_gaps(report: BenchmarkReport) -> List[Dict[str, Any]]:
        """Identify major compliance gaps"""
        gaps = []
        
        for result in report.results:
            if result.status == ControlStatus.FAIL:
                gap = {
                    "control_id": result.control_id,
                    "title": result.title,
                    "section": result.section,
                    "severity": getattr(result, 'severity', 'MEDIUM'),
                    "impact": result.impact or "Not specified",
                    "remediation_priority": JSONReporter._get_remediation_priority(result)
                }
                gaps.append(gap)
        
        # Sort by severity and return top gaps
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        gaps.sort(key=lambda x: severity_order.get(x['severity'], 99))
        
        return gaps[:10]  # Return top 10 gaps

    @staticmethod
    def _get_remediation_priority(result) -> str:
        """Get remediation priority based on severity and impact"""
        severity = getattr(result, 'severity', 'MEDIUM')
        
        if severity in ['CRITICAL', 'HIGH']:
            return 'IMMEDIATE'
        elif severity == 'MEDIUM':
            return 'HIGH'
        else:
            return 'MEDIUM'

    @staticmethod
    def _get_manual_verification_summary(report: BenchmarkReport) -> Dict[str, Any]:
        """Get summary of manual verification requirements"""
        manual_controls = [r for r in report.results if r.status == ControlStatus.MANUAL]
        
        sections_with_manual = {}
        for control in manual_controls:
            if control.section not in sections_with_manual:
                sections_with_manual[control.section] = []
            sections_with_manual[control.section].append({
                "control_id": control.control_id,
                "title": control.title,
                
                "severity": getattr(control, 'severity', 'MEDIUM'),
                "estimated_time": "5-15 minutes"
            })
        
        return {
            "total_manual_controls": len(manual_controls),
            "high_priority_manual": JSONReporter._count_high_priority_manual(report),
            "estimated_total_time": f"{len(manual_controls) * 10} minutes",
            "sections_requiring_manual_review": sections_with_manual,
            "verification_guidelines": [
                "Review each manual control carefully",
                "Document verification steps taken",
                "Maintain evidence for compliance audits",
                "Schedule regular manual reviews"
            ]
        }

    @staticmethod
    def _generate_recommendations(report: BenchmarkReport) -> Dict[str, Any]:
        """Generate actionable recommendations"""
        recommendations = {
            "immediate_actions": [],
            "short_term_improvements": [],
            "long_term_strategy": [],
            "manual_verification_plan": []
        }
        
        # Immediate actions (critical failures)
        for result in report.results:
            if (result.status == ControlStatus.FAIL and 
                getattr(result, 'severity', 'MEDIUM') == 'CRITICAL'):
                recommendations["immediate_actions"].append({
                    "control_id": result.control_id,
                    "action": f"Address critical failure: {result.title}",
                    "remediation": result.remediation or "See control documentation"
                })
        
        # Short-term improvements (high priority failures and manual controls)
        for result in report.results:
            if (result.status == ControlStatus.FAIL and 
                getattr(result, 'severity', 'MEDIUM') == 'HIGH'):
                recommendations["short_term_improvements"].append({
                    "control_id": result.control_id,
                    "action": f"Implement: {result.title}",
                    "remediation": result.remediation or "See control documentation"
                })
            elif (result.status == ControlStatus.MANUAL and 
                  getattr(result, 'severity', 'MEDIUM') in ['CRITICAL', 'HIGH']):
                recommendations["manual_verification_plan"].append({
                    "control_id": result.control_id,
                    "action": f"Manual review required: {result.title}",
                    "steps": result.manual_steps or [],
                    "remediation": result.remediation or "See control documentation"
                })
        
        # Long-term strategy
        if report.pass_percentage < 80:
            recommendations["long_term_strategy"].append({
                "area": "Overall Security Posture",
                "recommendation": "Develop comprehensive security improvement plan",
                "details": "Current pass rate is below recommended 80% threshold"
            })
        
        if report.manual > 0:
            recommendations["long_term_strategy"].append({
                "area": "Manual Process Automation",
                "recommendation": "Consider automating manual verification processes where possible",
                "details": f"{report.manual} controls currently require manual verification"
            })
        
        return recommendations
