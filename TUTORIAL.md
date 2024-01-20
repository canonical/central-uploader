# Project Built from Source (prerequisite)

In order to be able to use `central-uploader`, you need to make sure that your project complies to the following criteria.


## 0. Launchpad public git repo (optional)

Your project's source code has to reside in a Launchpad git repository

In case you may have multiple repositories to be bundled up in a single build, those repositories have to reside in
the Launchpad public git space, available to anyone who has a Launchpad account

In case your project repository is the same space where you want to apply your build mechanism, you can skip this step.


## 1. Launchpad build repository

The repository where the build process is to be performed has to reside in the internal Canonical Launchpad Artifactory repository.

This area is strictly managed within Canonical Launchpad CI Team, and is created on request.

You need to define a well-distinguishable branch for your actual build project (typically using version numbers of the project).


## 2. Launchpad build pipeline

Within your build repo, a `.launchpad.yaml` file (similar to GitHub pipeline declaratinos) has to exist, with steps
such as:

 - dependencies
 - build
 - release

This pipeline is executed on each git commit issued against this repository.
(If it doesn't, then it's likely to be an issue with the `.launchpad.yaml` file. If you would like to test it
locally, you can use the [lpci](https://lpci.readthedocs.io/en/latest/) tool, running `lpci clean; lpci run`.)

On a successful build, the following outputs MUST be generated:

 1. A tarball or zipfile format artifactory
 2. An SHA checksum of the above
 3. A zipfile generateted from the local maven repository cache (`.m2/repositories`)

NOTE: The artifactory tarball/zipfile has to correspond to the following naming terminology:
`<project-name>-<release>-ubuntu0-<TIMESTAMP>.(zip|tar.gz)`

Example: opensearch-2.10.0-ubuntu0-20240119181708.tar.gz


### Dependencies

The Canonical "build-from-source" procedure does not allow for any external access. Technically of course
a `.launchpad.yaml` may perform such builds. However such artifactory outputs don't comply to the process.

All dependencies of a Java application MUST be uploaded to the [Canonical Jfrog repository](https://canonical.jfrog.io/)


## 3. Launchpad project release pages

You have to set up a releases page for your project
See: https://help.launchpad.net/ on how to register a project

NOTE: The name of your project MUST end with "releases", such as `<my>-<little>-<app>-releases`

Example: https://launchpad.net/opensearch-releases
