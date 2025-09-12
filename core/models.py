"""
Core data models for the YugabyteDB CIS Benchmark Tool
"""

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ControlStatus(Enum):
    """Status of a control check"""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    INFO = "INFO"
    SKIP = "SKIP"


class CheckType(Enum):
    """Type of check to perform"""
    AUTOMATED = "Automated"
    MANUAL = "Manual"


class ProfileLevel(Enum):
    """CIS Profile Levels"""
    LEVEL1 = "Level 1"
    LEVEL2 = "Level 2"


@dataclass
class CISControl:
    """Detailed CIS Control specification"""
    control_id: str
    title: str
    profile_applicability: List[str]
    description: str
    rationale: str
    audit: str
    remediation: str
    impact: Optional[str] = None
    default_value: Optional[str] = None
    references: List[str] = None
    cis_controls: List[str] = None
    check_type: str = "Automated"
    section: str = ""

    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.cis_controls is None:
            self.cis_controls = []


@dataclass
class ControlResult:
    """Result of a control check"""
    control_id: str
    title: str
    status: ControlStatus
    message: str
    section: str = ""
    profile_level: str = ""
    remediation: Optional[str] = None
    expected: Optional[str] = None
    actual: Optional[str] = None
    severity: str = "MEDIUM"
    audit_command: Optional[str] = None
    impact: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'control_id': self.control_id,
            'title': self.title,
            'status': self.status.value,
            'message': self.message,
            'section': self.section,
            'profile_level': self.profile_level,
            'remediation': self.remediation,
            'expected': self.expected,
            'actual': self.actual,
            'severity': self.severity,
            'audit_command': self.audit_command,
            'impact': self.impact
        }


@dataclass
class SectionSummary:
    """Summary for each section"""
    section_name: str
    total_controls: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    pass_percentage: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class BenchmarkReport:
    """Complete benchmark report"""
    cluster_info: Dict[str, Any]
    scan_time: datetime
    total_checks: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    results: List[ControlResult]
    section_summaries: List[SectionSummary]
    profile_level: str = "Level 1"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'cluster_info': self.cluster_info,
            'scan_time': self.scan_time.isoformat(),
            'total_checks': self.total_checks,
            'passed': self.passed,
            'failed': self.failed,
            'warnings': self.warnings,
            'skipped': self.skipped,
            'profile_level': self.profile_level,
            'results': [result.to_dict() for result in self.results],
            'section_summaries': [summary.to_dict() for summary in self.section_summaries]
        }

    def get_pass_rate(self) -> float:
        """Calculate overall pass rate"""
        if self.total_checks == 0:
            return 0.0
        return (self.passed / self.total_checks) * 100

    def get_section_results(self, section_name: str) -> List[ControlResult]:
        """Get all results for a specific section"""
        return [result for result in self.results if result.section == section_name]

    def get_failed_results(self) -> List[ControlResult]:
        """Get all failed control results"""
        return [result for result in self.results if result.status == ControlStatus.FAIL]

    def get_results_by_status(self, status: ControlStatus) -> List[ControlResult]:
        """Get all results with specific status"""
        return [result for result in self.results if result.status == status]
