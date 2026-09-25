# ARGUS Graph Schema

Populated from a real Cartography run against our AWS + CloudGoat account on 2026-09-26.
This is the single source of truth for node/edge names — every later Rego rule,
mutation-engine mutator, and risk-scoring function reads field names from here.

> [!NOTE]
> Cartography prefixes AWS resource labels with `AWS` or standard AWS service names
> (e.g. `AWSRole`, `AWSUser`, `AWSPolicy`, `AWSEC2SecurityGroup`), rather than `IAMRole` or `IAMUser`.
> Resources with 0 instances in the account (such as `AWSS3Bucket` or `AWSRDSInstance`) do not
> appear in `CALL db.labels()` until at least one instance is created and synced.

## Node labels

| Label | Key properties observed | Notes |
|---|---|---|
| AWSAccount | id, name, inscope, account_mfa_enabled, users, roles, policies | Root node for the AWS account |
| AWSUser | name, arn, userid, path, createdate, passwordlastused, id | IAM users (includes CloudGoat user `raynor-cgidjq6epnjtgc`) |
| AWSRole | name, arn, roleid, path, createdate, id | IAM roles |
| AWSPolicy | name, arn, id, type | IAM managed policies (includes CloudGoat policy `cg-raynor-policy-cgidjq6epnjtgc`) |
| AWSPolicyStatement | action, effect, resource, sid, id | Statements parsed from IAM policies |
| AWSAccountAccessKey | accesskeyid, status, createdate, lastuseddate, lastusedservice, id | IAM access keys |
| AWSEC2SecurityGroup / EC2SecurityGroup | groupid, name, description, region, id | EC2 security groups |
| AWSIpPermissionInbound / IpPermissionInbound | groupid, ruleid, protocol, id | Ingress rules attached to security groups |
| IpRange / AWSIpRange | range, id | CIDR block definitions attached to IP rules |
| AWSVpc / VirtualNetwork | vpcid, primary_cidr_block, is_default, state, region, id | Virtual Private Clouds |
| AWSEC2Subnet / Subnet | subnet_id, cidr_block, availability_zone, vpc_id, region, id | Subnets within VPCs |
| AWSEC2NetworkAcl / EC2NetworkAcl | network_acl_id, vpc_id, is_default, region, arn, id | Network Access Control Lists |
| AWSEC2NetworkAclRule / EC2NetworkAclRule | rulenumber, ruleaction, egress, protocol, cidrblock, id | Rules within NACLs |
| AWSEC2RouteTable / EC2RouteTable | route_table_id, owner_id, main, region, id | VPC Route Tables |
| AWSS3Bucket | name, arn, region, id | S3 bucket (created when S3 buckets are present in account) |

## Relationship types

| Relationship | Typical pattern | Notes |
|---|---|---|
| RESOURCE | `(:AWSAccount)-[:RESOURCE]->(:AWSPrincipal)` | Account owns IAM users and roles |
| RESOURCE | `(:AWSAccount)-[:RESOURCE]->(:AWSEC2SecurityGroup)` | Account owns security groups |
| RESOURCE | `(:AWSAccount)-[:RESOURCE]->(:AWSVpc)` | Account owns VPCs |
| RESOURCE | `(:AWSAccount)-[:RESOURCE]->(:AWSEC2Subnet)` | Account owns subnets |
| RESOURCE | `(:AWSAccount)-[:RESOURCE]->(:AWSS3Bucket)` | Account owns S3 buckets (when present) |
| POLICY | `(:AWSUser)-[:POLICY]->(:AWSPolicy)` | User attached policy |
| POLICY | `(:AWSRole)-[:POLICY]->(:AWSPolicy)` | Role attached policy |
| STATEMENT | `(:AWSPolicy)-[:STATEMENT]->(:AWSPolicyStatement)` | Policy contains statement |
| AWS_ACCESS_KEY | `(:AWSPrincipal)-[:AWS_ACCESS_KEY]->(:AWSAccountAccessKey)` | User has active access key |
| OWNED_BY | `(:AWSAccountAccessKey)-[:OWNED_BY]->(:AWSPrincipal)` | Reverse link from access key to principal |
| TRUSTS_AWS_PRINCIPAL | `(:AWSPrincipal)-[:TRUSTS_AWS_PRINCIPAL]->(:AWSPrincipal)` | Trust relationship / assume role policy |
| MEMBER_OF_EC2_SECURITY_GROUP | `(:AWSIpPermissionInbound)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(:AWSEC2SecurityGroup)` | Ingress rule belongs to security group |
| MEMBER_OF_IP_RULE | `(:AWSIpRange)-[:MEMBER_OF_IP_RULE]->(:IpRule)` | CIDR range attached to rule |
| ALLOWS_TRAFFIC_FROM | `(:AWSEC2SecurityGroup)-[:ALLOWS_TRAFFIC_FROM]->(:AWSEC2SecurityGroup)` | SG references another SG in rule |
| MEMBER_OF_AWS_VPC | `(:AWSEC2Subnet)-[:MEMBER_OF_AWS_VPC]->(:AWSVpc)` | Subnet belongs to VPC |
| MEMBER_OF_AWS_VPC | `(:AWSEC2SecurityGroup)-[:MEMBER_OF_AWS_VPC]->(:AWSVpc)` | Security group belongs to VPC |
| ATTACHED_TO | `(:AWSInternetGateway)-[:ATTACHED_TO]->(:AWSVpc)` | Internet gateway attached to VPC |
| ROUTE | `(:AWSEC2RouteTable)-[:ROUTE]->(:AWSEC2Route)` | Route table contains routes |
| ROUTES_TO_GATEWAY | `(:AWSEC2Route)-[:ROUTES_TO_GATEWAY]->(:AWSInternetGateway)` | Route points to gateway |

## Full label list (raw output of `CALL db.labels()`)

```json
[
  "APIKey",
  "AWSAccount",
  "AWSAccountAccessKey",
  "AWSCidrBlock",
  "AWSEC2NetworkAcl",
  "AWSEC2NetworkAclRule",
  "AWSEC2Route",
  "AWSEC2RouteTable",
  "AWSEC2RouteTableAssociation",
  "AWSEC2SecurityGroup",
  "AWSEC2Subnet",
  "AWSInternetGateway",
  "AWSIpPermissionInbound",
  "AWSIpRange",
  "AWSIpRule",
  "AWSIpv4CidrBlock",
  "AWSManagedPolicy",
  "AWSPolicy",
  "AWSPolicyStatement",
  "AWSPrincipal",
  "AWSRole",
  "AWSRootPrincipal",
  "AWSServicePrincipal",
  "AWSUser",
  "AWSVpc",
  "AWSVpcEndpoint",
  "AWSVpnGateway",
  "AccountAccessKey",
  "EC2NetworkAcl",
  "EC2NetworkAclRule",
  "EC2Route",
  "EC2RouteTable",
  "EC2RouteTableAssociation",
  "EC2SecurityGroup",
  "EC2Subnet",
  "IpPermissionEgress",
  "IpPermissionInbound",
  "IpRange",
  "IpRule",
  "ModuleSyncMetadata",
  "NetworkAccessControl",
  "PermissionRole",
  "ServiceAccount",
  "Subnet",
  "SyncMetadata",
  "Tenant",
  "UserAccount",
  "VirtualNetwork"
]
```

## Full relationship type list (raw output of `CALL db.relationshipTypes()`)

```json
[
  "ALLOWS_TRAFFIC_FROM",
  "ASSOCIATION",
  "ATTACHED_TO",
  "AWS_ACCESS_KEY",
  "BLOCK_ASSOCIATION",
  "MEMBER_OF_AWS_VPC",
  "MEMBER_OF_EC2_SECURITY_GROUP",
  "MEMBER_OF_IP_RULE",
  "MEMBER_OF_NACL",
  "OWNED_BY",
  "PART_OF_SUBNET",
  "POLICY",
  "RESOURCE",
  "ROUTE",
  "ROUTES_TO_GATEWAY",
  "STATEMENT",
  "TRUSTS_AWS_PRINCIPAL"
]
```