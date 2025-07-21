# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""Utils module."""

import fnmatch
import logging
import os
import re
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Iterator

import requests
from requests.auth import HTTPBasicAuth

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)

PRODUCT_PATTERN = ".*-\\d+[.]\\d+[.]\\d+.*-ubuntu(0|[1-9][0-9]*)-(20\\d{2})[01][0-9][0-3][0-9][0-2]\\d[0-5]\\d[0-5]\\d\\S*"
TAG_PATTERN = "-(20\\d{2})[01][0-9][0-3][0-9][0-2]\\d[0-5]\\d[0-5]\\d\\S*"
RELEASE_VERSION = ".*-\\d+[.]\\d+[.]\\d+.*-ubuntu(0|[1-9][0-9]*)"

PATCH_VERSION = "ubuntu(0|[1-9][0-9]*)"

CUSTOM_KEYMAP = [".jar", ".pom", ".sha1", ".sha256", ".sha512"]

ARCHITECTURES = ["arm64", "amd64"]


def file_comparator(file: str) -> int:
    """Map file extension to int for upload ordering."""
    if os.path.splitext(file)[1] in CUSTOM_KEYMAP:
        return CUSTOM_KEYMAP.index(os.path.splitext(file)[1])
    return 100


def is_valid_release_version(release_version: str) -> bool:
    """Validate the release version."""
    try:
        p = re.compile(RELEASE_VERSION)
        if p.match(release_version):
            return True
    except Exception as e:
        raise ValueError("Name do not match the ") from e
    return False


def is_valid_product_name(product_name: str) -> bool:
    """Validate the name of the tarball."""
    try:
        p = re.compile(PRODUCT_PATTERN)
        if p.match(product_name):
            return True
    except Exception as e:
        raise ValueError("Name do not match the ") from e
    return False


def get_product_tags(
    repository_owner: str, project_name: str, product_name: str, product_version: str
):
    """Get the tags related to a product."""
    tags = get_repositories_tags(repository_owner, project_name)
    return [
        t
        for t in tags
        if t.startswith(f"{product_name}-{product_version}")
        and is_valid_release_version(t)
    ]


def get_library_tags(repository_owner: str, project_name: str, library_name: str):
    """Get the tags related to a library."""
    tags = get_repositories_tags(repository_owner, project_name)
    return [t for t in tags if t.startswith(f"{library_name}")]


def split_tag(release_tag: str):
    """
    Extract product name and version from release tag.

    eg. "opensearch-dashboards-2.19.2-ubuntu0" -> ("opensearch-dashboards", "2.19.2").
    """
    name_and_version = re.match(r"^(.*?)-(\d+(?:\.\d+)*)(?=-)", release_tag)
    if not name_and_version:
        raise ValueError(f"Invalid release tag: {release_tag}")
    return name_and_version.group(1), name_and_version.group(2)


def check_new_releases(
    output_directory: str,
    tarball_pattern: str,
    repository_owner: str,
    project_name: str,
):
    """Iterate over most recents releases and check if they need to be released."""
    assert output_directory
    logger.info(f"Analyzing directory: {output_directory}")
    folders_to_delete = []
    for release_directory in os.listdir(output_directory):
        tarball_name = None
        for filename in os.listdir(f"{output_directory}/{release_directory}"):
            if fnmatch.fnmatch(filename, tarball_pattern):
                tarball_name = filename
                break
        if not tarball_name:
            continue
        logger.debug(f"Tarball name: {tarball_name}")
        assert tarball_name
        new_release_version = get_version_from_tarball_name(tarball_name)
        logger.debug(f"new release name: {new_release_version}")
        product_name, product_version = split_tag(new_release_version)
        # check them against tags in Github
        related_tags = get_product_tags(
            repository_owner, project_name, product_name, product_version
        )
        logger.debug(f"Related tag: {related_tags}")
        # delete folder with release if already published
        if new_release_version in related_tags:
            folders_to_delete.append(release_directory)
            continue
        # check if the new release has a valid patch naming
        assert check_next_release_name(
            repository_owner,
            project_name,
            product_name,
            product_version,
            new_release_version,
        )

    for folder in folders_to_delete:
        logger.info(f"Deleting folder: {folder}")
        shutil.rmtree(f"{output_directory}/{folder}")


def check_new_library(
    output_directory: str,
    library_pattern: str,
    repository_owner: str,
    project_name: str,
):
    """Iterate over most recents libraries and check if they need to be released."""
    assert output_directory
    logger.info(f"Analyzing directory: {output_directory}")
    folders_to_delete = []
    for release_directory in os.listdir(output_directory):
        library_name = None
        for filename in os.listdir(f"{output_directory}/{release_directory}"):
            if fnmatch.fnmatch(filename, library_pattern):
                # get library name without extension
                library_name = filename.rsplit(".", 1)[0]
                break
        logger.debug(f"Library name: {library_name}")
        assert library_name
        # check them against tags in Github
        related_tags = get_library_tags(repository_owner, project_name, library_name)
        logger.debug(f"Related tag: {related_tags}")
        # delete folder with release if already published
        if library_name in related_tags:
            folders_to_delete.append(release_directory)
            continue

    for folder in folders_to_delete:
        logger.info(f"Deleting folder: {folder}")
        shutil.rmtree(f"{output_directory}/{folder}")


def get_patch_version(release_version: str) -> int:
    """Return the patch version from the release version."""
    if not is_valid_release_version(release_version):
        raise ValueError(f"The release version '{release_version}' is not valid!")

    match = re.search(PATCH_VERSION, release_version)
    if match:
        return int(match.group(1))
    raise ValueError(f"Invalid release_version {release_version}")


def check_next_release_name(
    repository_owner: str,
    project_name: str,
    product_name: str,
    product_version: str,
    release_version: str,
) -> bool:
    """Check that the new release name is valid."""
    related_tags = get_product_tags(
        repository_owner, project_name, product_name, product_version
    )
    if not is_valid_release_version(release_version):
        raise ValueError(
            f"The inserted product version is not valid: {release_version}"
        )
    new_patch_version = get_patch_version(release_version)
    last_released_patch = -1
    if len(related_tags) != 0:
        last_tag = sorted(
            related_tags, key=lambda x: get_patch_version(x), reverse=True
        )[0]
        last_released_patch = get_patch_version(last_tag)
    if new_patch_version != last_released_patch + 1:
        logger.warning(f"Invalid release name: {release_version}")
        return False
    return True


def iter_paths(folder: str | Path, regex: re.Pattern | None = None) -> Iterator[Path]:
    """Directory tree generator."""
    folder_path = Path(folder) if isinstance(folder, str) else folder

    for root, _, files in os.walk(folder):
        root_path = Path(root).relative_to(folder_path)

        if not regex or regex.fullmatch(str(root_path)):
            yield folder_path / root_path
        for file in files:
            full_path = root_path / file
            if not regex or regex.fullmatch(str(full_path)):
                yield folder_path / full_path


def upload(
    file_regex: str,
    maven_repository_archive: str,
    artifactory_repository: str,
    artifactory_username: str,
    artifactory_password: str,
):
    """Upload jars to artifactory."""
    logger.info("Start the upload process")
    os.mkdir("tmp")
    logger.info("Extract local maven")
    with zipfile.ZipFile(maven_repository_archive, "r") as zip:
        zip.extractall("tmp/")

    folder = "tmp/repository/"

    subdirs = {
        element.parent if element.is_file() else element
        for element in iter_paths(folder, re.compile(file_regex))
    }

    logger.debug(f"Number of subdir to upload: {len(subdirs)}")
    for subdir in subdirs:
        files = sorted(os.listdir(subdir), key=file_comparator)
        for file in files:
            # skip temp files or metadata
            if file.startswith("_") or file.endswith(".repositories"):
                continue
            url = f"{artifactory_repository}{subdir.relative_to(folder)}/{file}"
            logger.debug(f"upload url: {url}")
            headers = {"Content-Type": "application/java-application"}
            r = requests.put(
                url,
                headers=headers,
                data=open(subdir / file, "rb"),
                auth=HTTPBasicAuth(artifactory_username, artifactory_password),
            )
            assert r.status_code == 201

    shutil.rmtree("tmp")
    logger.info("End of the upload process")


def get_version_from_tarball_name(tarball_name: str, multiarch: bool = False) -> str:
    """Extract the tag name that will used for the release."""
    assert is_valid_product_name(tarball_name)

    try:
        p = re.compile(TAG_PATTERN)
        items = p.split(tarball_name)
        arch = None
        if multiarch:
            for arch in ARCHITECTURES:
                if arch in tarball_name:
                    break
            arch = arch or "unknown"
            return f"{items[0]}-{arch}"
        else:
            return items[0]
    except Exception as e:
        raise ValueError("ERROR") from e


def iter_pages(url: str) -> Iterator[dict]:
    """Iterate over the elements across the pages of a paginated endpoint."""
    while url:
        r = requests.get(url)
        logger.debug(f"status code: {r.status_code}")
        assert r.status_code == 200

        for item in r.json():
            yield item

        url = r.links["next"]["url"] if "next" in r.links else ""


def get_repositories_tags(owner: str, repository_name) -> list[str]:
    """Return the list of tags in the database."""
    url = f"https://api.github.com/repos/{owner}/{repository_name}/tags"
    tags = []
    for item in iter_pages(url):
        if "name" in item:
            tags.append(item["name"])
        else:
            logger.warning(f"No key 'name' in Github API response: {item}")

    return tags
