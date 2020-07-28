# Pipefitter
A golang-based Lambda job that will accept cloudwatch events or timers to update
IP-based target groups used with NLBs across a variety of regions.

## Using Pipefitter
Pipefitter assumes you have IP-based target groups every region you support 
PrivateLink in. You can choose to not use them in the regions you have targets in.

Set up your NLBs and VPC Endpoints however you choose (AWS Console,
Cloudformation, Terraform, etcetera). Add a tag named `pipefitter` with the
ID value you generate. 

Set up your targets to have some sort of role tag and value, so Pipefitter
can find them.

Deploy lambda. Deliver your service.

## Configuring Pipefitter
Pipefitter is configured using environment variables.

| Variable                    | Required | Description                                                                   |
|-----------------------------|----------|-------------------------------------------------------------------------------|
| PIPEFITTER_ID               | Yes      | A generated ID for this Pipefitter instance - used to find managed resources. |
| PIPEFITTER_PL_ALLOWED_PEERS | Yes      | Comma-separated list of AWS numbers you want to allow peering with.           |
| PIPEFITTER_PL_REGIONS       | Yes      | Comma-separated list of regions you offer PL connectivity in.                 |
| PIPEFITTER_TARGET_PORT      | Yes      | Port of the service you're hosting                                            |
| PIPEFITTER_TARGET_REGIONS   | Yes      | Comma-separated list of regions you have targets in.                          |
| PIPEFITTER_TARGET_TAG       | Yes      | Name of the tag used to identify your target hosts.                           |
| PIPEFITTER_TARGET_VALUE     | Yes      | Value of the tag used to identify your target hosts.                          |
| PIPEFITTER_UPDATE_ALL_IPS   | No       | Set to `1` to update target groups in PL regions you have targets in.         |

