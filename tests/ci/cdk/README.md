## Overview

ACCP CI uses AWS CDK to define and deploy AWS resources (e.g. AWS CodeBuild, ECR).

## CI Setup

### Before running CDK command:

* Install [AWS CDK](https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html#getting_started_install)
* Install [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)
* [Connect AWS CodeBuild with GitHub](https://docs.aws.amazon.com/codebuild/latest/userguide/sample-access-tokens.html)
  * Note: This step should grant AWS CodeBuild with access to create WebHook.
  * For team AWS account, AWS CodeBuild is connected with GitHub through GitHub OAuth.
    * step 1: go to AWS CodeBuild console.
    * step 2: create a CodeBuild project.
    * step 3: change **Source provider** to **GitHub**. 
    * step 4: click **Connect using OAuth** and **Connect to GitHub**.
    * step 5: follow the OAuth app to grant access.

### Minimal permissions:

To setup or update the CI in your account you will need the following IAM permissions. 

* CodeBuild
  * codebuild:Create*
  * codebuild:Update*
  * codebuild:Batch*
  * codebuild:StartBuild
  * codebuild:StopBuild
  * codebuild:RetryBuild
* ECR
  * ecr:Batch*
  * ecr:Get*
  * ecr:Describe*
  * ecr:List*
  * ecr:Initiate*
  * ecr:Upload*
  * ecr:Complete*
  * ecr:Put*

### Commands

Notes:
* `AWS_ACCOUNT` specifies the AWS account the CI wishes to propogate resources to. Default is the ACCP team account if not defined.
* `GITHUB_REPO_OWNER` specifies the GitHub repo targeted by this CI setup. Default is `corretto` if not defined.
* `GITHUB_BRANCH` specifies the branch on the GitHub repo that has the CI scripts you wish to deploy. Default is `develop` if not defined.
* https://github.com/${GITHUB_REPO_OWNER}/amazon-corretto-crypto-provider.git

To set up the ACCP CI (create/update docker images and deploy CI resources), run command:
```
./run-cdk.sh --aws-account=${AWS_ACCOUNT} --github-repo-owner=${GITHUB_REPO_OWNER}  --github-source-version=${GITHUB_BRANCH} --action deploy-ci
```

To create/update Linux Docker images, run command:
```
./run-cdk.sh --aws-account=${AWS_ACCOUNT} --github-repo-owner=${GITHUB_REPO_OWNER}  --github-source-version=${GITHUB_BRANCH} --action build-linux-img
```

To deploy CI resources for the ACCP CI, run command:
```
./run-cdk.sh --aws-account=${AWS_ACCOUNT} --github-repo-owner=${GITHUB_REPO_OWNER}  --github-source-version=${GITHUB_BRANCH} --action update-ci
```

To destroy ACCP CI resources created above, run command:
```
# NOTE: this command will destroy all resources (AWS CodeBuild and ECR).
./run-cdk.sh --aws-account=${AWS_ACCOUNT} --github-repo-owner=${GITHUB_REPO_OWNER}  --github-source-version=${GITHUB_BRANCH} --action destroy-ci
```

For help, run command:
```
./run-cdk.sh --help
```

## Files

Inspired by [AWS CDK blog](https://aws.amazon.com/blogs/developer/getting-started-with-the-aws-cloud-development-kit-and-python/)

Below is CI file structure.

```
(.env) $ tree
.
├── README.md
├── app.py
├── cdk
│   ├── __init__.py
│   ├── ecr_stack.py
│   ├── ...
├── cdk.json
├── requirements.txt
├── run-cdk.sh
├── setup.py
└── util
    ├── __init__.py
    └── env_util.py
    └── ...
```
* `README.md` — The introductory README for this project.
* `app.py` — The “main” for this sample application.
* `cdk.json` — A configuration file for CDK that defines what executable CDK should run to generate the CDK construct tree.
* `cdk` — A CDK module directory
* `requirements.txt` — This file is used by pip to install all of the dependencies for your application. In this case, it contains only -e . This tells pip to install the requirements specified in setup.py. It also tells pip to run python setup.py develop to install the code in the cdk module so that it can be edited in place.
* `setup.py` — Defines how this Python package would be constructed and what the dependencies are.

## Development Reference

The `cdk.json` file tells the CDK Toolkit how to execute this CDK app `app.py`.

This project is set up like a standard Python project.  The initialization
process also creates a virtualenv within this project, stored under the .env
directory.  To create the virtualenv it assumes that there is a `python3`
(or `python` for Windows) executable in your path with access to the `venv`
package. If for any reason the automatic creation of the virtualenv fails,
you can create the virtualenv manually.

To manually create a virtualenv on MacOS and Linux:

```
$ python3 -m venv .env
```

After the init process completes and the virtualenv is created, you can use the following
step to activate your virtualenv.

```
$ source .env/bin/activate
```

If you are a Windows platform, you would activate the virtualenv like this:

```
% .env\Scripts\activate.bat
```

Once the virtualenv is activated, you can install the required dependencies.

```
$ pip install -r requirements.txt
```

At this point you can now synthesize the CloudFormation template for this code.

```
$ cdk synth
```

To add additional dependencies, for example other CDK libraries, just add
them to your `setup.py` file and rerun the `pip install -r requirements.txt`
command.

### Useful commands

 * `cdk ls`          list all stacks in the app
 * `cdk synth`       emits the synthesized CloudFormation template
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk docs`        open CDK documentation
 
### Useful Docker image build commands

**Notes**:
* below commands replicate steps that are performed in `run-cdk.sh` but use default values set in `cdk/util/metadata.py`.
* Always clean up resources set up for Docker image build.
  * `cdk destroy accp-docker-image-build-* --force`

#### Linux Docker image build

```bash
# Launch Linux Docker image CodeBuild resources.
cdk deploy accp-docker-image-build-linux --require-approval never

# Trigger CodeBuild to build Linux Docker Images
aws codebuild start-build-batch --project-name accp-docker-image-build-linux

# Go to AWS console, you can check CodeBuild by clicking "Developer Tools > CodeBuild > Build projects".
```
