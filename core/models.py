"""
Core data models for the YugabyteDB CIS Benchmark Tool
"""

from dataclasses import asdict, dataclass, field
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
    MANUAL = "MANUAL"


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
    manual_steps: Optional[List[str]] = None
    references: Optional[List[str]] = None
    compliance_frameworks: Optional[List[str]] = None

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
    manual: int = 0
    
    def __post_init__(self):
        """Calculate pass percentage based on automated tests only"""
        automated_total = self.passed + self.failed + self.skipped
        if automated_total > 0:
            self.pass_percentage = (self.passed / automated_total) * 100
        else:
            self.pass_percentage = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class BenchmarkReport:
    """Complete benchmark report"""
    cluster_info: Dict[str, Any]
    scan_time: datetime
    results: List[ControlResult]
    profile_level: str = "Level 1"
    
    section_summaries: List[SectionSummary] = field(init=False)
    total_checks: int = field(init=False)
    passed: int = field(init=False)
    failed: int = field(init=False)
    warnings: int = field(init=False)
    skipped: int = field(init=False)
    manual: int = field(init=False)
    pass_percentage: float = field(init=False)

    def __post_init__(self):
        """Calculate summary statistics"""
        self.total_checks = len(self.results)
        self.passed = sum(1 for r in self.results if r.status == ControlStatus.PASS)
        self.failed = sum(1 for r in self.results if r.status == ControlStatus.FAIL)
        self.warnings = sum(1 for r in self.results if r.status == ControlStatus.WARN)
        self.skipped = sum(1 for r in self.results if r.status == ControlStatus.SKIP)
        self.manual = sum(1 for r in self.results if r.status == ControlStatus.MANUAL)
        
        automated_total = self.passed + self.failed + self.skipped
        if automated_total > 0:
            self.pass_percentage = (self.passed / automated_total) * 100
        else:
            self.pass_percentage = 0.0
        
        self._generate_section_summaries()

    def _generate_section_summaries(self):
        """Generate section summaries from results"""
        sections = {}
        
        for result in self.results:
            if result.section not in sections:
                sections[result.section] = {
                    'total': 0,
                    'passed': 0,
                    'failed': 0,
                    'warnings': 0,
                    'skipped': 0,
                    'manual': 0
                }
            
            sections[result.section]['total'] += 1
            
            if result.status == ControlStatus.PASS:
                sections[result.section]['passed'] += 1
            elif result.status == ControlStatus.FAIL:
                sections[result.section]['failed'] += 1
            elif result.status == ControlStatus.WARN:
                sections[result.section]['warnings'] += 1
            elif result.status == ControlStatus.SKIP:
                sections[result.section]['skipped'] += 1
            elif result.status == ControlStatus.MANUAL:
                sections[result.section]['manual'] += 1
        
        self.section_summaries = []
        for name, stats in sections.items():
            section_summary = SectionSummary(
                section_name=name,
                total_controls=stats['total'],
                passed=stats['passed'],
                failed=stats['failed'],
                warnings=stats['warnings'],
                skipped=stats['skipped'],
                manual=stats['manual']
            )
            self.section_summaries.append(section_summary)

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


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark execution"""
    profile_level: str = "L1"  # L1, L2
    host: str = "localhost"
    port: int = 5433
    database: str = "yugabyte"
    username: str = "yugabyte"
    password: Optional[str] = None
    ssl_mode: str = "prefer"
    connect_timeout: int = 30
    
    skip_manual: bool = False           # Skip manual controls entirely
    include_info: bool = True           # Include informational controls
    fail_on_manual: bool = False        # Treat manual controls as failures
    sections: Optional[List[str]] = None  # Specific sections to run
    controls: Optional[List[str]] = None  # Specific controls to run
    
    output_formats: List[str] = field(default_factory=lambda: ["html", "json"])
    output_dir: str = "./reports"
    include_passed: bool = True         # Include passed controls in detailed reports
    verbose: bool = False
    
    manual_verification_mode: str = "mark"  # "mark", "skip", "fail"
    prompt_for_manual: bool = False


@dataclass
class ManualControl:
    """Definition of a manual control"""
    control_id: str
    title: str
    description: str
    verification_steps: List[str]
    expected_result: str
    remediation: str
    impact: str
    profile_level: str
    section: str
    references: Optional[List[str]] = None
    compliance_frameworks: Optional[List[str]] = None
    severity: str = "MEDIUM"


@dataclass
class ComplianceFramework:
    """Compliance framework mapping"""
    name: str                           # CIS, SOC2, PCI-DSS, etc.
    version: str
    control_mappings: Dict[str, str]    # control_id -> framework_control_id
    requirements: List[str]             # List of framework requirements

def get_status_priority(status: ControlStatus) -> int:
    """Get priority for status sorting (lower number = higher priority)"""
    priority_map = {
        ControlStatus.FAIL: 1,
        ControlStatus.MANUAL: 2,
        ControlStatus.SKIP: 3,
        ControlStatus.INFO: 4,
        ControlStatus.PASS: 5
    }
    return priority_map.get(status, 999)


def get_status_color(status: ControlStatus) -> str:
    """Get color code for status"""
    color_map = {
        ControlStatus.PASS: "#22C55E",      # Green
        ControlStatus.FAIL: "#EF4444",      # Red
        ControlStatus.SKIP: "#6B7280",      # Gray
        ControlStatus.INFO: "#06B6D4",      # Cyan
        ControlStatus.MANUAL: "#8B5CF6"     # Purple
    }
    return color_map.get(status, "#6B7280")


def get_status_icon(status: ControlStatus) -> str:
    """Get icon for status"""
    icon_map = {
        ControlStatus.PASS: "✅",
        ControlStatus.FAIL: "❌",
        ControlStatus.SKIP: "⏭️",
        ControlStatus.INFO: "ℹ️",
        ControlStatus.MANUAL: "👤"
    }
    return icon_map.get(status, "❓")


def create_manual_control_result(
    control_id: str,
    title: str,
    section: str,
    profile_level: str,
    verification_steps: List[str],
    remediation: str = "",
    impact: str = "",
    references: List[str] = None
) -> ControlResult:
    """Create a ControlResult for a manual control"""
    return ControlResult(
        control_id=control_id,
        title=title,
        status=ControlStatus.MANUAL,
        message="Manual verification required - please review the verification steps below",
        profile_level=profile_level,
        section=section,
        manual_steps=verification_steps,
        remediation=remediation,
        impact=impact,
        references=references or []
    )