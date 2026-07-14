#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import os
import re
import tempfile
import zipfile
from argparse import ArgumentParser, Namespace

from prettytable import PrettyTable

from .utils import remove_ascii_colors
from .validate import LogParser, Report

SUMMARY_RE = re.compile(
    r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)"
)


def parse_args() -> Namespace:
    """Parse command line args."""
    parser = ArgumentParser()
    parser.add_argument(
        "-a", "--archive-logs", help="Path to the archive where run logs are stored."
    )
    return parser.parse_args()


class NifiLogParser(LogParser):
    """Parser for the NiFi (JUnit/Surefire) integration tests."""

    def parse_log_archive(self, log_archive: str) -> Report:
        """Parse the log archive and extract the test results."""
        filename = None
        succeeded = failed = errors = skipped = total = 0
        clean_lines = []
        failed_tests = []
        executed_modules = []

        with tempfile.TemporaryDirectory() as tmpdirname:
            print("created temporary directory", tmpdirname)
            with zipfile.ZipFile(log_archive, "r") as zip_ref:
                zip_ref.extractall(tmpdirname)
                log_directory = f"{tmpdirname}/logs/"
                for log_file in os.listdir(log_directory):
                    if ".out" not in log_file:
                        continue
                    filename = log_file
                    print("Analyzed log file: " + log_file)
                    with open(f"{log_directory}/{log_file}", "r") as file:
                        for line in file:
                            clean_line = remove_ascii_colors(line.strip())
                            clean_lines.append(clean_line)

                            if "<<< FAILURE!" in clean_line or "<<< ERROR!" in clean_line:
                                failed_tests.append(clean_line)

                            if clean_line.startswith("Building nifi"):
                                executed_modules.append(clean_line.split(" ")[1])

                            if "Time elapsed" in clean_line or "-- in" in clean_line:
                                continue
                            m = SUMMARY_RE.search(clean_line)
                            if m:
                                run, f, e, s = (int(g) for g in m.groups())
                                total += run
                                failed += f
                                errors += e
                                skipped += s

        succeeded = total - failed - errors - skipped
        return Report(
            log_file=filename,
            succeeded=succeeded,
            failures=failed,
            errors=errors,
            skipped=skipped,
            total=total,
            executed_modules=executed_modules,
            raw=clean_lines,
            failed_tests=failed_tests,
        )  # type: ignore


if __name__ == "__main__":
    args = parse_args()
    log_reports = []
    zip_file_folder = args.archive_logs
    print("Start analyze the logs from the different runs...")
    logs_archives = os.listdir(zip_file_folder)
    print(f"Number of runs: {len(logs_archives)}")
    parser = NifiLogParser()
    for log_archive in logs_archives:
        with tempfile.TemporaryDirectory() as tmpdirname:
            print("created temporary directory", tmpdirname)
            log_archive_path = f"{zip_file_folder}/{log_archive}"
            res = parser.parse_log_archive(log_archive_path)
            log_reports.append(res)
            with open(f"/tmp/cleaned_{log_archive}", "w") as f:
                for line in res.raw:
                    f.write(f"{line}\n")

    table = PrettyTable()
    table.field_names = [
        "Test",
        "Succeeded",
        "Failures",
        "Errors",
        "Skipped",
        "Total",
        "Executed test modules",
        "Failed Tests",
    ]
    for report in log_reports:
        table.add_row(
            [
                report.log_file,
                report.succeeded,
                report.failures,
                report.errors,
                report.skipped,
                report.total,
                len(report.executed_modules),
                len(report.failed_tests),
            ]
        )
    print(table)

    print("\n\nFailed tests:")
    for report in log_reports:
        print("-" * 75)
        print(f"Filename: {report.log_file}")
        print(f"Number of failed tests: {len(report.failed_tests)}")
        print("=" * 75)
        for failed_test in report.failed_tests:
            print(f"\t {failed_test}")
        print("-" * 75)
    print("End of the process.")
