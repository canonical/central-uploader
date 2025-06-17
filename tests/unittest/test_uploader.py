# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


from unittest.mock import patch

from uploader.utils import (
    check_next_release_name,
    get_patch_version,
    get_repositories_tags,
    get_version_from_tarball_name,
    is_valid_product_name,
)


def test_valid_product_name():
    """This function test the validity of product name."""

    v_1 = "spark-3.4.1-ubuntu1-20230821132449-bin-k8s.tgz"
    v_2 = "spark-3.3.1-ubuntu1-20231201152409-bin-kub.zip"
    v_3 = "opensearch-2.9.0-ubuntu1-20230821132449-linux-x64.tar.gz"
    v_4 = "spark-3.4.1-ubuntu100-20230821132449-bin-k8s.tgz"
    v_5 = "opensearch-2.8.0-ubuntu0-20230920150138-linux-x64.tar.gz"
    v_6 = "opensearch-2.10.0-ubuntu0-20231004122318-linux-x64.tar.gz"
    v_7 = "spark-3.4.1-ubuntu1-20231004201041-bin-k8s.tgz"
    v_8 = "kafka_2.13-3.5.1-ubuntu0-20231004130455.tgz"
    v_9 = "spark-4.0.0-preview1-ubuntu0-20240813100410-bin-k8s.tgz"
    v_10 = "kafka_2.13-4.0.0-ubuntu0-20231004130455.tgz"
    i_1 = "spark-3.4-ubuntu-1-20230821132449-bin.tgz"
    i_2 = "spark-3.4.1-ubuntu-01-20230821132449-bin-k8s.tgz"
    i_3 = "spark-3.4.1-ubuntu-01-20230821132469-bin-.tgz"
    i_4 = "spark-3.4.1-ubuntu01-20230821132439-bin-k8s.tgz"
    i_5 = "spark-3.4.1-ubuntu-1-20230821132449-bin-k8s.tgz"

    valid_names = [v_1, v_2, v_3, v_4, v_5, v_6, v_7, v_8, v_9, v_10]
    invalid_names = [i_1, i_2, i_3, i_4, i_5]

    for v in valid_names:
        assert is_valid_product_name(v)

    for v in invalid_names:
        assert not is_valid_product_name(v)


def test_get_version_tarball_name():
    """This function test the correct extraction of the tag name."""

    v_1 = "spark-3.4.1-ubuntu0-20230821132449-bin.tgz"
    v_2 = "spark-3.3.1-ubuntu1-20231201152409-bin.zip"
    v_3 = "opensearch-2.9.0-ubuntu1-20230821132449-linux-x64.tar.gz"
    v_4 = "spark-3.4.1-ubuntu100-20230821132449-bin.tgz"
    v_5 = "opensearch-2.8.0-ubuntu0-20230920150138-linux-x64.tar.gz"
    v_6 = "spark-4.0.0-preview1-ubuntu0-20240813100410-bin-k8s.tgz"

    t_1 = "spark-3.4.1-ubuntu0"
    t_2 = "spark-3.3.1-ubuntu1"
    t_3 = "opensearch-2.9.0-ubuntu1"
    t_4 = "spark-3.4.1-ubuntu100"
    t_5 = "opensearch-2.8.0-ubuntu0"
    t_6 = "spark-4.0.0-preview1-ubuntu0"
    t_7 = "kafka_2.13-4.0.0-ubuntu0"
    t_8 = "kafka_2.13-4.0.0-ubuntu1"

    tarball_names = [v_1, v_2, v_3, v_4, v_5, v_6]
    tags = [t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8]

    for idx, tarball_name in enumerate(tarball_names):
        assert get_version_from_tarball_name(tarball_name) == tags[idx]


def test_get_repositories_tags():
    """This function test the retrivial of repository tags."""
    tags = get_repositories_tags("canonical", "kafka-operator")
    assert len(tags) > 0


def test_check_next_release_name():
    """This function test that the new release name is valid."""
    with patch("uploader.utils.get_product_tags", return_value=["spark-3.4.1-ubuntu0"]):
        assert check_next_release_name(
            "test-owner", "test-project", "spark", "3.4.1", "spark-3.4.1-ubuntu1"
        )
        assert not check_next_release_name(
            "test-owner",
            "test-project",
            "spark",
            "3.4.1",
            "spark-3.4.1-ubuntu2",
        )
    with patch("uploader.utils.get_product_tags", return_value=[]):
        assert check_next_release_name(
            "test-owner", "test-project", "spark", "3.4.1", "spark-3.4.1-ubuntu0"
        )
        assert not check_next_release_name(
            "test-owner",
            "test-project",
            "spark",
            "3.4.1",
            "spark-3.4.1-ubuntu1",
        )


def test_get_patch_version():
    """This function test the extraction of the patch version."""

    r_1 = "spark-3.4.1-ubuntu0"
    r_2 = "spark-3.3.1-ubuntu1"
    r_3 = "opensearch-2.9.0-ubuntu1"
    r_4 = "spark-3.4.1-ubuntu100"

    p_1 = 0
    p_2 = 1
    p_3 = 1
    p_4 = 100

    release_names = [r_1, r_2, r_3, r_4]
    patches = [p_1, p_2, p_3, p_4]

    for idx, release_name in enumerate(release_names):
        assert get_patch_version(release_name) == patches[idx]
