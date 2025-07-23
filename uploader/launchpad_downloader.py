#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""Launchpad downloader module."""

import argparse
import collections
import fnmatch
import logging
import os
import sys
import urllib.request
from argparse import Namespace
from dataclasses import dataclass
from typing import Any
from urllib.error import URLError
from urllib.parse import unquote

import httplib2
from launchpadlib.launchpad import Launchpad

LP_APP = "data-platform-java-build-app"
LP_SERVER = "production"
LP_VERSION = "devel"

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)


@dataclass
class CIBuild:
    """CI build information."""

    branch_name: str
    build_log_url: str
    ci_results: str
    date_built: str
    commit_sha1: str
    build_state: str
    artifact_urls: list[str]


def _get_tokenized_librarian_url(lp: Launchpad, file_url: str) -> str:
    """Use OAuth to get a tokenised URL for private downloads."""
    # rewrote url
    rewritten_url = file_url.replace("code.launchpad.net/", "api.launchpad.net/devel/")
    logger.debug("Rewrote {} to {} for OAuth access...".format(file_url, rewritten_url))
    logger.debug("Using OAuth'd client to get launchpad.net URL with token...")
    try:
        ret = lp._browser._connection.request(rewritten_url, redirections=0)
        # Print the response to assist debugging failures
        logger.debug(ret)
        raise AssertionError("No redirect to download from, we can't proceed")
    except httplib2.RedirectLimit as e:
        return str(e.response["location"])


def parse_args() -> Namespace:
    """Parse command line args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repository-url",
        type=str,
        required=True,
        help="The url of the Launchpad repository.",
    )
    parser.add_argument(
        "--branch-prefix",
        type=str,
        required=True,
        help="The prefix name of the desired branches, if not specified all branches will be scanned.",
    )
    parser.add_argument(
        "--credential-file",
        type=str,
        required=True,
        help="The path of the file that contains the Launchpad credentials.",
    )
    parser.add_argument(
        "--output-folder",
        type=str,
        required=True,
        help="The output folder where the built software will be downloaded.",
    )
    parser.add_argument(
        "--tarball-pattern", type=str, help="Tarball pattern name.", required=True
    )
    parser.add_argument(
        "--check-all-runs",
        type=bool,
        help="Check all runs until one tarball that matches the regex is found.",
        required=False,
        default=False,
    )
    return parser.parse_args()


def get_launchpad(credential_file: str) -> Launchpad:
    """Get launchpad handler."""
    return Launchpad.login_with(
        LP_APP,
        LP_SERVER,
        credentials_file=credential_file,
        version=LP_VERSION,
        timeout=30,
    )


def get_branches_in_repo(
    lp: Launchpad, repo_url: str, branch_prefix: str
) -> dict[str, list[Any]]:
    """Fetch branches from repo."""
    # get repository
    repo = lp.git_repositories.getByPath(path=repo_url)

    # get all branches
    branches = list(repo.branches)

    # collect reports for the desired branches
    branch_map = collections.defaultdict(list)
    for branch in branches:
        if branch_prefix and branch_prefix not in branch.path:
            continue

        for report in repo.getStatusReports(commit_sha1=branch.commit_sha1):
            branch_map[branch.path].append(report)

    return branch_map


def get_build_runs_by_branch(
    branches: dict[str, list[Any]],
) -> dict[str, list[CIBuild]]:
    """Fetch the list of build runs by branch."""
    branch_builds: dict[str, list[CIBuild]] = {}

    # iterate over builds
    for branch, ci_runs in branches.items():
        logger.info(f"Checking builds for branch: {branch}")
        if branch not in branch_builds:
            branch_builds[branch] = []

        for run in ci_runs:
            ci_build = run.ci_build

            # only consider successfully built
            if "Successfully built" not in ci_build.buildstate:
                continue

            artifact_urls = []
            for file_url in run.ci_build.getFileUrls():
                artifact_urls.append(file_url)

            branch_builds[branch].append(
                CIBuild(
                    branch,
                    ci_build.build_log_url,
                    ci_build.results,
                    ci_build.datebuilt,
                    ci_build.commit_sha1,
                    ci_build.buildstate,
                    artifact_urls,
                )
            )

    return branch_builds


def download_build_artifacts_by_branch(
    launchpad: Launchpad, branch: str, build_run, output_folder: str
) -> None:
    """Download build artifacts of a build run."""
    output_directory = f"{output_folder}/{str(branch).split('/')[-1]}"
    os.makedirs(output_directory, exist_ok=True)

    for url_file in build_run.artifact_urls:
        url = _get_tokenized_librarian_url(launchpad, url_file)
        # download each file related to the build
        file_name = unquote(str(url_file).split("/")[-1])
        try:
            urllib.request.urlretrieve(url, f"{output_directory}/{file_name}")
        except URLError as e:
            raise RuntimeError(
                "Failed to download '{}'. '{}'".format(url, e.reason)
            ) from e


def main():
    """Download latest build software from Launchpad repository."""
    args = parse_args()

    # Get Launchpad instance
    launchpad = get_launchpad(args.credential_file)

    # fetch repositories
    branches = get_branches_in_repo(launchpad, args.repository_url, args.branch_prefix)
    if not branches:
        raise ValueError(
            "No items to download please checks the repository or branch prefix"
        )

    # fetch list of builds by branch
    branch_builds = get_build_runs_by_branch(branches)

    logger.info(f"Number of branches detected: {len(branch_builds)}")

    logger.info("Downloading available builts...")
    # iterate over each branch and download locally the latest build
    for branch, runs in branch_builds.items():
        if not runs:
            continue
        logger.info(f"Start downloading files for branch {branch}")
        if args.check_all_runs:
            last_runs = sorted(runs, key=lambda x: x.date_built, reverse=True)
        else:
            last_runs = [sorted(runs, key=lambda x: x.date_built, reverse=True)[0]]

        # check if the successful build contains the desired artifact
        artifact_exist = False
        for last_run in last_runs:
            for url_file in last_run.artifact_urls:
                # check if tarball is part of the build artifacts
                file_name = unquote(str(url_file).split("/")[-1])
                if fnmatch.fnmatch(file_name, args.tarball_pattern):
                    artifact_exist = True
                    break
            if artifact_exist:
                break

        logger.info(f"Artifact exist: {artifact_exist}")
        if artifact_exist:
            logger.info(f"Downloading artifacts from branch: {branch}")
            download_build_artifacts_by_branch(
                launchpad, branch, last_run, args.output_folder
            )
        else:
            logger.warning(f"Branch {branch} does not contains are artifact!")


if __name__ == "__main__":
    main()
