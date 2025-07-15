#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Dataclasses and abstraction for validation module."""

from abc import abstractmethod
from dataclasses import dataclass, field


@dataclass
class Report:
    """Test summary."""

    log_file: str = ""
    succeeded: int = 0
    failures: int = 0
    errors: int = 0
    canceled: int = 0
    pending: int = 0
    skipped: int = 0
    ignored: int = 0
    total: int = 0
    executed_modules: list = field(default_factory=list)
    raw: list = field(default_factory=list)
    failed_tests: list = field(default_factory=list)


class LogParser:
    """Abstract parser class."""

    @abstractmethod
    def parse_log_archive(self, log_archive: str) -> Report:
        """Parse the log archive and extract the test results."""
        pass
