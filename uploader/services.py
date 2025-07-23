# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""Services module."""

import logging
from argparse import ArgumentParser, Namespace
from enum import Enum

from uploader.utils import (
    check_new_library,
    check_new_releases,
    get_version_from_tarball_name,
    is_valid_product_name,
    upload,
)

logger = logging.getLogger(__name__)


class Actions(str, Enum):
    """Action enum."""

    VERSION = "get-version"
    VERSION_MULTIARCH = "get-version-multiarch"
    VALID_NAME = "validate-name"
    CHECK_VERSION = "check-releases"
    CHECK_LIBRARY_VERSION = "check-library-releases"
    UPLOAD = "upload-product-jars"


def create_services_parser(parser: ArgumentParser) -> ArgumentParser:
    """Create CLI parser."""
    subparser = parser.add_subparsers(dest="action")
    subparser.required = True

    parser_tag = subparser.add_parser(
        Actions.VERSION.value, help="Retrieve software version from tarball name."
    )
    parser_tag.add_argument(
        "-n", "--name", type=str, help="The product name to be checked.", required=True
    )

    parser_tag_multiarch = subparser.add_parser(
        Actions.VERSION_MULTIARCH.value,
        help="Retrieve software version from tarball name.",
    )
    parser_tag_multiarch.add_argument(
        "-n", "--name", type=str, help="The product name to be checked.", required=True
    )
    parser_tag_multiarch.add_argument(
        "--series", type=str, help="The ubuntu series of that file."
    )

    parser_validation = subparser.add_parser(Actions.VALID_NAME.value)
    parser_validation.add_argument(
        "-n",
        "--name",
        type=str,
        help="Validate the name of the tarball.",
        required=True,
    )

    parser_check_version = subparser.add_parser(
        Actions.CHECK_VERSION.value,
        help="Check if the name of the tarball is valid with respect to the published tarballs.",
    )
    parser_check_version.add_argument(
        "-o",
        "--output-directory",
        type=str,
        help="Path of the directory where releases are downloaded.",
        required=True,
    )
    parser_check_version.add_argument(
        "-t", "--tarball-pattern", type=str, help="Tarball pattern name.", required=True
    )
    parser_check_version.add_argument(
        "-r", "--repository-owner", type=str, help="Repository owner.", required=True
    )
    parser_check_version.add_argument(
        "-p", "--project-name", type=str, help="Project name.", required=True
    )
    parser_check_version.add_argument(
        "-s", "--series", type=str, help="Ubuntu series.", required=False
    )
    parser_check_version.add_argument(
        "--architecture", type=str, help="The architecture to use", required=False
    )

    parser_check_library_version = subparser.add_parser(
        Actions.CHECK_LIBRARY_VERSION.value,
        help="Check if the name of the library is valid with respect to the published library.",
    )
    parser_check_library_version.add_argument(
        "-o",
        "--output-directory",
        type=str,
        help="Path of the directory where releases are downloaded.",
        required=True,
    )
    parser_check_library_version.add_argument(
        "-l", "--library-pattern", type=str, help="Library pattern name.", required=True
    )
    parser_check_library_version.add_argument(
        "-r", "--repository-owner", type=str, help="Repository owner.", required=True
    )
    parser_check_library_version.add_argument(
        "-p", "--project-name", type=str, help="Project name.", required=True
    )

    parser_upload = subparser.add_parser(
        Actions.UPLOAD.value,
        help="Upload jars contained in the tarball to artifactory.",
    )
    parser_upload.add_argument(
        "-l", "--library-pattern", type=str, help="Library pattern name.", required=True
    )
    parser_upload.add_argument(
        "-r",
        "--mvn-repository",
        type=str,
        help="Maven repository archive path.",
        required=True,
    )
    parser_upload.add_argument(
        "-a", "--artifactory-url", type=str, help="Artifactory url.", required=True
    )
    parser_upload.add_argument(
        "-u",
        "--artifactory-username",
        type=str,
        help="Artifactory username.",
        required=True,
    )
    parser_upload.add_argument(
        "-z",
        "--artifactory-password",
        type=str,
        help="Artifactory password.",
        required=True,
    )

    return parser


def main(args: Namespace):
    """Define main entrypoint."""
    if args.action == Actions.VERSION:
        if not is_valid_product_name(args.name):
            raise ValueError("Invalid product name!")
        print(get_version_from_tarball_name(args.name))

    elif args.action == Actions.VERSION_MULTIARCH:
        if not is_valid_product_name(args.name):
            raise ValueError("Invalid product name!")
        print(
            get_version_from_tarball_name(
                args.name,
                series=args.series,
                architecture=args.architecture,
            )
        )

    elif args.action == Actions.VALID_NAME:
        if not is_valid_product_name(args.name):
            raise ValueError("Invalid product name!")

    elif args.action == Actions.CHECK_VERSION:
        check_new_releases(
            args.output_directory,
            args.tarball_pattern,
            args.repository_owner,
            args.project_name,
            args.series,
            args.architecture,
        )
    elif args.action == Actions.CHECK_LIBRARY_VERSION:
        check_new_library(
            args.output_directory,
            args.library_pattern,
            args.repository_owner,
            args.project_name,
        )
    elif args.action == Actions.UPLOAD:
        upload(
            args.library_pattern,
            args.mvn_repository,
            args.artifactory_url,
            args.artifactory_username,
            args.artifactory_password,
        )
    else:
        raise ValueError(f"Option: {args.action} is not a valid option!")


if __name__ == "__main__":
    args = create_services_parser(
        ArgumentParser(description="Services for the Github Central Uploader")
    ).parse_args()
    main(args)
