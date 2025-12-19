#!/usr/bin/env python3
"""
Base class for all scanner modules
Provides standard interface for all modules
"""

from typing import Dict, List, Optional, Any
import logging


class ScannerModule:
    """Base class for all scanner modules."""

    def __init__(self, module_name: str, config: Dict, logger: logging.Logger):
        self.module_name = module_name
        self.config = config
        self.logger = logger
        self.results = {
            'module_name': module_name,
            'vulnerabilities': [],
            'warnings': [],
            'info': [],
            'status': 'pending',
            'execution_time': 0
        }

    def setup(self):
        """Setup the module (override in subclasses)."""
        pass

    def run(self, target_url: str) -> Dict:
        """
        Run the module scan.
        Must return results in standard format.
        """
        raise NotImplementedError("Subclasses must implement run() method")

    def cleanup(self):
        """Cleanup resources (override in subclasses)."""
        pass

    def get_results(self) -> Dict:
        """Get module results in standard format."""
        return self.results

    def add_vulnerability(self, vulnerability: Dict):
        """Add a vulnerability finding."""
        self.results['vulnerabilities'].append(vulnerability)

    def add_warning(self, warning: Dict):
        """Add a warning finding."""
        self.results['warnings'].append(warning)

    def add_info(self, info: Dict):
        """Add informational finding."""
        self.results['info'].append(info)

    def set_status(self, status: str):
        """Set module status (pending, running, completed, failed)."""
        self.results['status'] = status