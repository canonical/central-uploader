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
from argparse import Namespace
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

import httpx2
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


def _rewrite_artifact_url_for_api(file_url: str) -> str:
    """Rewrite a Launchpad web artifact URL to its API equivalent."""
    return file_url.replace("code.launchpad.net/", "api.launchpad.net/devel/")


def _get_oauth_headers(lp: Launchpad, url: str) -> dict[str, str]:
    """Sign a request using Launchpad OAuth credentials."""
    headers: dict[str, str] = {}
    lp._browser._connection.authorizer.authorizeRequest(url, "GET", None, headers)
    return headers


def _download_artifact(lp: Launchpad, file_url: str, destination: str) -> None:
    """Download a Launchpad build artifact via the OAuth-capable API URL."""
    api_url = _rewrite_artifact_url_for_api(file_url)
    headers = _get_oauth_headers(lp, api_url)
    timeout = httpx2.Timeout(connect=30.0, read=600.0, write=60.0, pool=30.0)

    logger.debug("Downloading artifact via rewritten API URL: %s", api_url)
    with httpx2.Client(follow_redirects=True, timeout=timeout) as client:
        with client.stream("GET", api_url, headers=headers) as response:
            response.raise_for_status()
            final_url = str(response.url)
            if "/+login" in final_url or final_url.endswith("+login"):
                raise RuntimeError(
                    f"Artifact request was redirected to Launchpad login: {final_url}"
                )
            with open(destination, "wb") as downloaded_file:
                for chunk in response.iter_bytes(chunk_size=1024 * 1024):
                    if chunk:
                        downloaded_file.write(chunk)


def _selected_artifact_urls(
    artifact_urls: list[str], artifact_pattern: str, download_repository_zip: bool
) -> list[str]:
    """Filter artifacts to the minimum set used by downstream workflows."""
    file_urls_by_name = {
        unquote(str(url_file).split("/")[-1]): url_file for url_file in artifact_urls
    }
    selected_names = {
        file_name
        for file_name in file_urls_by_name
        if fnmatch.fnmatch(file_name, artifact_pattern)
    }
    selected_names.update({f"{file_name}.sha512" for file_name in selected_names})
    if download_repository_zip and "repository.zip" in file_urls_by_name:
        selected_names.add("repository.zip")

    return [
        file_urls_by_name[file_name]
        for file_name in file_urls_by_name
        if file_name in selected_names
    ]


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
    parser.add_argument(
        "--download-repository-zip",
        action="store_true",
        help="Also download repository.zip for workflows that upload Java dependencies.",
        required=False,
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
    launchpad: Launchpad,
    branch: str,
    build_run,
    output_folder: str,
    artifact_pattern: str,
    download_repository_zip: bool,
) -> None:
    """Download the build artifacts needed by downstream workflows."""
    output_directory = f"{output_folder}/{str(branch).split('/')[-1]}"
    os.makedirs(output_directory, exist_ok=True)

    selected_artifact_urls = _selected_artifact_urls(
        build_run.artifact_urls, artifact_pattern, download_repository_zip
    )
    logger.info(
        "Selected %d/%d artifacts for branch %s",
        len(selected_artifact_urls),
        len(build_run.artifact_urls),
        branch,
    )

    for url_file in selected_artifact_urls:
        file_name = unquote(str(url_file).split("/")[-1])
        destination = f"{output_directory}/{file_name}"
        try:
            _download_artifact(launchpad, url_file, destination)
        except httpx2.HTTPError as e:
            raise RuntimeError(
                "Failed to download '{}'. '{}'".format(url_file, e)
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
                launchpad,
                branch,
                last_run,
                args.output_folder,
                args.tarball_pattern,
                args.download_repository_zip,
            )
        else:
            logger.warning(f"Branch {branch} does not contains are artifact!")


if __name__ == "__main__":
    main()
