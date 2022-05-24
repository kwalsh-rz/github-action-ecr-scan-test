# Github action to evaluate the results of the AWS ECR image scan

This action will retrieve the results of the AWS ECR image scan and evaluate the results based on the inputs supplied. A threshold is provided and any vulnerabilities at, or above, this threshold will cause the action to fail. If there are vulnerabilities present that have been deemed safe to ignore, they may be added to the ignore list.

## Inputs

### `awsRegion`

The region where the ECR repository is located. **Default:** "us-east-1"

### `awsAccessKey`

**Required**: The AWS Access Key with read access to the ECR repository.

### `awsSecretAccessKey`

**Required**: The WS Secret Access Key with read access to the ECR repository.

### `imageTag`

**Required**: The image tag to scan.

### `repository`

**Required**: The ECR repository, eg rzsoftware/redzone-deployer.

### `failThreshold`

Fail if any vulnerabilities equal to or over this severity level are detected. Valid values: critical, high, medium, low, informational. **Default:** "high"

### `ignoreList`

List of CVEs that can be safely ignored and should not fail the scan. List should be separated by commas. eg 'CVE-2022-1234,CVE-2022-4321'

## Outputs

### `vulnerabilities`

The number of vulnerabilities found at or above the specified failure threshold and not included on the ignore list. A value greater than 0 will fail the action.

## Example usage

Currently, actions contained in a private repository cannot be used from another repository. As a work-around until this functionality is delivered, we first checkout the code from the repository containing the action (requires use of a token).
See the discussion [here](https://github.community/t/github-action-action-in-private-repository/16063/40) for more information.

```
- uses: actions/checkout@v2
  with:
    repository: rzsoftware/github-action-ecr-scan
    token: ${{ secrets.REDZONE_DEPLOYER_ACTION_TOKEN }}
    path: github-action
- name: Evaluate Image Scan
  id: ecr-scan-image
  uses: ./github-action
  with:
    awsRegion: us-east-1
    awsAccessKey: ${{ secrets.AWS_ACCESS_KEY_ID }}
    awsSecretAccessKey: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    imageTag: ${{ steps.image_names.outputs.scan_image_tag }}   #The output from a previous job/step that builds and publishes the image
    repository: XXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com/rzops/rzio
    failThreshold: high
    ignoreList: CVE-2022-1234,CVE-2022-4321
```