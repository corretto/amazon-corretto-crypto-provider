# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

$ECS_REPO=$args[0]

if ($args[0] -eq $null) {
    # This is a ECS repository in our CI account
    $ECS_REPO="838297025124.dkr.ecr.us-west-2.amazonaws.com/accp-docker-images-windows-x86"
}

Write-Host "$ECS_REPO"

docker tag vs2015_corretto ${ECS_REPO}:vs2015_corretto_latest
docker tag vs2015_corretto ${ECS_REPO}:vs2015_corretto-$(Get-Date -UFormat %Y-%m-%d-%H)
docker push ${ECS_REPO}:vs2015_corretto_latest
docker push ${ECS_REPO}:vs2015_corretto-$(Get-Date -UFormat %Y-%m-%d-%H)

docker tag vs2017_corretto ${ECS_REPO}:vs2017_corretto_latest
docker tag vs2017_corretto ${ECS_REPO}:vs2017_corretto-$(Get-Date -UFormat %Y-%m-%d-%H)
docker push ${ECS_REPO}:vs2017_corretto_latest
docker push ${ECS_REPO}:vs2017_corretto-$(Get-Date -UFormat %Y-%m-%d-%H)
