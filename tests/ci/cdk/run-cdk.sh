#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -exuo pipefail

# -e: Exit on any failure
# -x: Print the command before running
# -u: Any variable that is not set will cause an error if used
# -o pipefail: Makes sure to exit a pipeline with a non-zero error code if any command in the pipeline exists with a
#              non-zero error code.

function delete_container_repositories() {
  ecr_repos=$(aws ecr describe-repositories)
  if [[ "${ecr_repos}" == *"${ECR_LINUX_X86_REPO_NAME}"* ]]; then
    aws ecr delete-repository --repository-name "${ECR_LINUX_X86_REPO_NAME}" --force
  fi
}

function destroy_ci() {
  if [[ "${CDK_DEPLOY_ACCOUNT}" == "838297025124" ]]; then
    echo "destroy_ci should not be executed on team account."
    exit 1
  fi
  cdk destroy accp-* --force
  # CDK stack destroy does not delete s3 bucket automatically.
  delete_s3_buckets
  # CDK stack destroy does not delete ecr automatically.
  delete_container_repositories
}

function destroy_docker_img_build_stack() {
  if [[ "${IMG_BUILD_STATUS}" == "Failed" ]]; then
    echo "Docker images build failed. AWS resources of building Docker images is kept for debug."
    exit 1
  fi
  # Destroy all temporary resources created for all docker image build.
  cdk destroy accp-docker-image-build-* --force
  # CDK stack destroy does not delete s3 bucket automatically.
  delete_s3_buckets
}

function create_linux_docker_img_build_stack() {
  # Clean up build stacks if exists.
  destroy_docker_img_build_stack
  # Deploy accp ci stacks.
  # When repeatedly deploy, error 'EIP failed Reason: Maximum number of addresses has been reached' can happen.
  # https://forums.aws.amazon.com/thread.jspa?messageID=952368
  # Workaround: go to AWS EIP console, release unused IP.
  cdk deploy accp-docker-image-build-linux --require-approval never
}

function create_github_ci_stack() {
  cdk deploy accp-ci-* --require-approval never
}

function run_linux_img_build() {
  # https://awscli.amazonaws.com/v2/documentation/api/latest/reference/codebuild/start-build-batch.html
  build_id=$(aws codebuild start-build-batch --project-name accp-docker-image-build-linux | jq -r '.buildBatch.id')
  export ACCP_LINUX_BUILD_BATCH_ID="${build_id}"
}

function linux_docker_img_build_status_check() {
  export IMG_BUILD_STATUS='Failed'
  # Every 5 min, this function checks if the linux docker image batch code build finished successfully.
  # Normally, docker img build can take up to 1 hour. Here, we wait up to 30 * 5 min.
  for i in {1..30}; do
    # https://docs.aws.amazon.com/cli/latest/reference/codebuild/batch-get-build-batches.html
    build_batch_status=$(aws codebuild batch-get-build-batches --ids "${ACCP_LINUX_BUILD_BATCH_ID}" | jq -r '.buildBatches[0].buildBatchStatus')
    if [[ ${build_batch_status} == 'SUCCEEDED' ]]; then
      export IMG_BUILD_STATUS='Success'
      echo "Code build ${ACCP_LINUX_BUILD_BATCH_ID} finished successfully."
      return
    elif [[ ${build_batch_status} == 'FAILED' ]]; then
      echo "Code build ${ACCP_LINUX_BUILD_BATCH_ID} failed."
      exit 1
    else
      echo "${i}: Wait 5 min for docker image build job finish."
      sleep 300
    fi
  done
  echo "Code build ${ACCP_LINUX_BUILD_BATCH_ID} takes more time than expected."
  exit 1
}

function build_linux_docker_images() {
  # Always destroy docker build stacks (which include EC2 instance) on EXIT.
  trap destroy_docker_img_build_stack EXIT

  # Create/update aws-ecr repo.
  cdk deploy accp-ecr-linux-* --require-approval never

  # Create docker image build stack.
  create_linux_docker_img_build_stack

  echo "Activating AWS CodeBuild to build Linux aarch & x86 docker images."
  run_linux_img_build

  echo "Waiting for docker images creation. Building the docker images need to take 1 hour."
  # TODO(CryptoAlg-624): These image build may fail due to the Docker Hub pull limits made on 2020-11-01.
  linux_docker_img_build_status_check
}

function setup_ci() {
  build_linux_docker_images

  create_github_ci_stack
}

###########################
# Main and related helper #
###########################

function script_helper() {
  cat <<EOF
This script uses CDK to deploy/destroy AWS resources defined in the accp cdk app.

For accp continuous integration setup, this script uses aws cli to build some non-AWS resources(e.g. Docker image).

Options:
    --help                       Displays this help
    --aws-account                AWS account for CDK deploy/destroy. Default to '838297025124'.
    --aws-region                 AWS region for AWS resources creation. Default to 'us-west-2'.
    --github-repo-owner          GitHub repository owner. Default to 'corretto'.
    --github-source-version      GitHub source version. Default to 'main'.
    --action                     Required. The value can be
                                   'deploy-ci': deploys accp ci. This includes AWS and Docker image resources creation.
                                   'update-ci': update accp ci. This only update AWS CodeBuild for GitHub CI.
                                   'destroy-ci': destroys AWS and Docker image resources used by accp ci.
                                   'destroy-img-stack': destroys AWS resources created during built of Docker images.
                                   'build-linux-img': builds Linux Docker image used by accp ci.
                                                After image build, AWS resources are cleaned up.
                                   'diff': compares the specified stack with the deployed stack.
                                   'synth': synthesizes and prints the CloudFormation template for the stacks.
EOF
}

function export_global_variables() {
  # If these variables are not set or empty, defaults are export.
  if [[ -z "${CDK_DEPLOY_ACCOUNT+x}" || -z "${CDK_DEPLOY_ACCOUNT}" ]]; then
    export CDK_DEPLOY_ACCOUNT='838297025124'
  fi
  if [[ -z "${CDK_DEPLOY_REGION+x}" || -z "${CDK_DEPLOY_REGION}" ]]; then
    export CDK_DEPLOY_REGION='us-west-2'
  fi
  if [[ -z "${GITHUB_REPO_OWNER+x}" || -z "${GITHUB_REPO_OWNER}" ]]; then
    export GITHUB_REPO_OWNER='corretto'
  fi
  if [[ -z "${GITHUB_SOURCE_VERSION+x}" || -z "${GITHUB_SOURCE_VERSION}" ]]; then
    export GITHUB_SOURCE_VERSION='main'
  fi
  # Other variables for managing resources.
  DATE_NOW="$(date +%Y-%m-%d-%H-%M)"
  export GITHUB_REPO='amazon-corretto-crypto-provider'
  export ECR_LINUX_X86_REPO_NAME='accp-docker-images-linux-x86'
  export IMG_BUILD_STATUS='unknown'
}

function main() {
  # parse arguments.
  while [[ $# -gt 0 ]]; do
    case ${1} in
    --help)
      script_helper
      exit 0
      ;;
    --aws-account)
      export CDK_DEPLOY_ACCOUNT="${2}"
      shift
      ;;
    --aws-region)
      export CDK_DEPLOY_REGION="${2}"
      shift
      ;;
    --github-repo-owner)
      export GITHUB_REPO_OWNER="${2}"
      shift
      ;;
    --github-source-version)
      export GITHUB_SOURCE_VERSION="${2}"
      shift
      ;;
    --action)
      export ACTION="${2}"
      shift
      ;;
    *)
      echo "${1} is not supported."
      exit 1
      ;;
    esac
    # Check next option -- key/value.
    shift
  done

  # Make sure action is set.
  if [[ -z "${ACTION+x}" || -z "${ACTION}" ]]; then
    echo "${ACTION} is required input."
    exit 1
  fi

  # Export global variables, which provides the contexts needed by ci setup/destroy.
  export_global_variables

  # Execute the action.
  case ${ACTION} in
  deploy-ci)
    setup_ci
    ;;
  update-ci)
    create_github_ci_stack
    ;;
  destroy-ci)
    destroy_ci
    ;;
  destroy-img-stack)
    destroy_docker_img_build_stack
    ;;
  build-linux-img)
    build_linux_docker_images
    ;;
  synth)
    cdk synth accp-ci-*
    ;;
  diff)
    cdk diff accp-ci-*
    ;;
  *)
    echo "--action is required. Use '--help' to see allowed actions."
    exit 1
    ;;
  esac
}

# Invoke main
main "$@"
