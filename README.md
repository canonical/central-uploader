# central-uploader

The `central-uploader` tool is to enable application release artifacts to Launchpad project pages.


# How it works

In order to be able to use the `central-uploader`, we need a Launchpad project, with a build proces,
producing artifacts as described in the [Project Built from Source (prerequisite)](./TUTORIAL.md) section below.

The `central-uploader`'s task in the chain is to download already existing artifacts from the
strictly protected internal Canonical Launchpad Artifactory repository, and publish them
to the project's public Launchpad Releases space.


## Registering a project

If you want to register your project with the `central-uploader`, you need to add a section
to the `products.json` file describing access to the project, and run the pipelines.

Already existing sections should give good guideline about what to add. As you may find, much of the content is
just repetatively to be copy-pasted, while other information is project-specific.


Note that
 - the `lp-building-branch-prefix` has to correspond to the release branch naming terminology of
   of the Project's Canonical Launchpad Artifactory repository. 
 - `tarball-regex` has to correspond to the artifactory output name
 - the `lp-consumer-key`, `lp-access-token`, `lp-access-secret`, `artifactory-user`, `artifactory-token` fields
   are to be defined the same for all project (i.e. to be copied)


## Publishing a release

There are regular executions of the `central-uploader` Release pipelines, but they can also be triggered manually.

Within this pipeline 

 1. Existing artifacts are downloaded from the project's Launchpad SOSS build space
 2. A new Github Release is created for the project within the scope of the `central-uploader` repository
 3. A new tag is also created with the release here
 4. The artifacts are uploaded to the project's public Launchpad Releases space


## Testing

When triggering your first pipeline runs, keep in mind that a release is only to be published once.
If you would like to re-run the publishing method for testing purposes, you need to make sure that
starting from item 2. of the list above all traces of the previous publish attemt under the same version are removed.
