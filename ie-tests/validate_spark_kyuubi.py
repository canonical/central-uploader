#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Spark and Kyuubi integration test validation module."""

import os
import tempfile
import zipfile
from argparse import ArgumentParser, Namespace

from prettytable import PrettyTable

from .utils import remove_ascii_colors
from .validate import LogParser, Report


def parse_args() -> Namespace:
    """Parse command line args."""
    parser = ArgumentParser()
    parser.add_argument(
        "-a", "--archive-logs", help="Path to the archive where run logs are stored."
    )

    return parser.parse_args()


class SparkLogParser(LogParser):
    """Parser for the Spark/Kyyubi integration tests."""

    def parse_log_archive(self, log_archive: str) -> Report:
        """Parse the log archive and extract the test results."""
        filename = None
        succeeded = 0
        failed = 0
        canceled = 0
        ignored = 0
        pending = 0
        clean_lines = []
        failed_tests = []
        executed_modules = []
        with tempfile.TemporaryDirectory() as tmpdirname:
            print("created temporary directory", tmpdirname)
            with zipfile.ZipFile(log_archive, "r") as zip_ref:
                zip_ref.extractall(tmpdirname)
                log_directory = f"{tmpdirname}/logs/"
                log_files = os.listdir(log_directory)
                for log_file in log_files:
                    if ".out" not in log_file:
                        continue
                    filename = log_file
                    print("Analyzed log file: " + log_file)
                    file = open(f"{log_directory}/{log_file}", "r")
                    # Read each line in the file
                    for line in file:
                        clean_line = remove_ascii_colors(line.strip())
                        clean_lines.append(clean_line)
                        if "*** FAILED ***" in clean_line:
                            failed_tests.append(clean_line)

                        if "-" in clean_line:
                            test_name = clean_line.split("-")[1].strip()
                            executed_modules.append(test_name)

                        if clean_line.startswith("Tests:"):
                            items = clean_line.split(",")
                            succeeded += int(items[0].split(" ")[-1])
                            failed += int(items[1].split(" ")[-1])
                            canceled += int(items[2].split(" ")[-1])
                            ignored += int(items[3].split(" ")[-1])
                            pending += int(items[4].split(" ")[-1])

        total = succeeded + failed + canceled + ignored + pending
        return Report(
            log_file=filename,
            succeeded=succeeded,
            failures=failed,
            canceled=canceled,
            ignored=ignored,
            pending=pending,
            total=total,
            executed_modules=executed_modules,
            raw=clean_lines,
            failed_tests=failed_tests,
        )  # type: ignore


if __name__ == "__main__":
    # Read collections of logs
    args = parse_args()
    log_reports = []
    zip_file_folder = args.archive_logs
    print("Start analyze the logs from the different runs...")
    logs_archives = os.listdir(zip_file_folder)
    print(f"Number of runs: {len(logs_archives)}")
    parser = SparkLogParser()
    for log_archive in logs_archives:
        # Extract zip file and extract key stats.
        with tempfile.TemporaryDirectory() as tmpdirname:
            print("created temporary directory", tmpdirname)
            log_archive_path = f"{zip_file_folder}/{log_archive}"
            # extract results from logs
            res = parser.parse_log_archive(log_archive_path)
            log_reports.append(res)
            # write cleaned version of the file
            with open(f"/tmp/cleaned_{log_archive}", "w") as f:
                for line in res.raw:
                    f.write(f"{line}\n")

    table = PrettyTable()
    table.field_names = [
        "Test",
        "Succeeded",
        "Failed",
        "Canceled",
        "Ignored",
        "Pending",
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
                report.canceled,
                report.ignored,
                report.pending,
                report.total,
                len(report.executed_modules),
                len(report.failed_tests),
            ]
        )

    print(table)
    # print failed tests over the runs
    print("\n\n")
    print("Failed tests:")
    for report in log_reports:
        print(
            "---------------------------------------------------------------------------"
        )
        print(f"Filename: {report.log_file}")
        print(f"Number of failed tests: {len(report.failed_tests)}")
        print(
            "==========================================================================="
        )
        for failed_test in report.failed_tests:
            print(f"\t {failed_test}")
        print(
            "---------------------------------------------------------------------------"
        )
    print("End of the process.")
