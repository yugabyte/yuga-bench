"""
CIS Specification Loader for YugabyteDB CIS Benchmark Tool
"""

import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml

from core.models import CISControl


class CISSpecificationLoader:
    """Load CIS specifications from organized directory structure"""

    def __init__(self, specs_directory: str):
        self.specs_directory = Path(specs_directory)
        self.sections = {}
        self.all_controls = []

    def load_all_specifications(self) -> List[CISControl]:
        """Load all CIS control specifications from directory structure"""
        if not self.specs_directory.exists():
            raise FileNotFoundError(f"Specifications directory not found: {self.specs_directory}")

        # Clear previous data
        self.all_controls.clear()
        self.sections.clear()

        # Load controls from each section directory
        section_dirs = sorted([d for d in self.specs_directory.iterdir() if d.is_dir()])

        for section_dir in section_dirs:
            section_name = self._clean_section_name(section_dir.name)
            self._load_section_controls(section_dir, section_name)

        return self.all_controls

    def _clean_section_name(self, dir_name: str) -> str:
        """Remove the alphabetic prefix (A-, B-, C-, etc.) from directory name"""
        # Remove patterns like "A-", "B-", etc. from the beginning
        if len(dir_name) > 2 and dir_name[1] == '-' and dir_name[0].isalpha():
            return dir_name[2:]  # Remove "A-", "B-", etc.
        return dir_name

    def _load_section_controls(self, section_dir: Path, section_name: str):
        """Load controls from a specific section directory"""
        controls_file = section_dir / 'controls.yaml'

        if not controls_file.exists():
            logging.warning(f"No controls.yaml found in {section_dir}")
            return

        try:
            with open(controls_file, 'r', encoding='utf-8') as f:
                section_data = yaml.safe_load(f)

            if not section_data:
                logging.warning(f"Empty or invalid YAML in {controls_file}")
                return

            section_info = section_data.get('section', {})
            controls_data = section_data.get('controls', [])

            if not controls_data:
                logging.warning(f"No controls found in {controls_file}")
                return

            for control_data in controls_data:
                try:
                    control = self._create_control_from_data(control_data, section_name)
                    self.all_controls.append(control)
                except Exception as e:
                    logging.error(f"Error creating control from {control_data.get('id', 'unknown')}: {e}")

            self.sections[section_name] = {
                'info': section_info,
                'controls': len(controls_data),
                'directory': section_dir.name
            }

            logging.info(f"Loaded {len(controls_data)} controls from section: {section_name}")

        except yaml.YAMLError as e:
            logging.error(f"YAML parsing error in {controls_file}: {e}")
        except Exception as e:
            logging.error(f"Error loading controls from {controls_file}: {e}")

    def _create_control_from_data(self, control_data: Dict[str, Any], section_name: str) -> CISControl:
        """Create a CISControl object from YAML data"""
        required_fields = ['id', 'title']
        for field in required_fields:
            if field not in control_data:
                raise ValueError(f"Missing required field '{field}' in control data")

        return CISControl(
            control_id=str(control_data['id']),
            title=str(control_data['title']),
            profile_applicability=control_data.get('profile_applicability', []),
            description=control_data.get('description', ''),
            rationale=control_data.get('rationale', ''),
            audit=control_data.get('audit', ''),
            remediation=control_data.get('remediation', ''),
            impact=control_data.get('impact'),
            default_value=control_data.get('default_value'),
            references=control_data.get('references', []),
            cis_controls=control_data.get('cis_controls', []),
            check_type=control_data.get('type', 'Automated'),
            section=section_name
        )

    def get_sections_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all loaded sections"""
        return self.sections

    def get_controls_by_section(self, section_name: str) -> List[CISControl]:
        """Get all controls for a specific section"""
        return [control for control in self.all_controls if control.section == section_name]

    def get_control_by_id(self, control_id: str) -> CISControl:
        """Get a specific control by its ID"""
        for control in self.all_controls:
            if control.control_id == control_id:
                return control
        raise ValueError(f"Control with ID '{control_id}' not found")

    def validate_specifications(self) -> Dict[str, List[str]]:
        """Validate loaded specifications and return any issues"""
        issues = {
            'errors': [],
            'warnings': []
        }

        # Check for duplicate control IDs
        control_ids = [control.control_id for control in self.all_controls]
        duplicates = set([x for x in control_ids if control_ids.count(x) > 1])
        if duplicates:
            issues['errors'].extend([f"Duplicate control ID: {dup}" for dup in duplicates])

        # Check for controls without audit commands
        for control in self.all_controls:
            if not control.audit.strip():
                issues['warnings'].append(f"Control {control.control_id} has no audit command")

            if not control.remediation.strip():
                issues['warnings'].append(f"Control {control.control_id} has no remediation")

        return issues
