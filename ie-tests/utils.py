#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Utils for test validation module."""

import re


def remove_ascii_colors(line):
    """Clean the line from ascii color code."""
    ansi_escape = re.compile(
        r"""
    \x1B  # ESC
    (?:   # 7-bit C1 Fe (except CSI)
        [@-Z\\-_]
    |     # or [ for CSI, followed by a control sequence
        \[
        [0-?]*  # Parameter bytes
        [ -/]*  # Intermediate bytes
        [@-~]   # Final bytere
    )
""",
        re.VERBOSE,
    )
    cleaned_line = ansi_escape.sub("", line.strip())
    return cleaned_line
