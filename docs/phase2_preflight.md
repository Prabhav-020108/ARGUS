# Phase 2 Preflight Health Report

Date: 2026-10-02
Environment: Windows PowerShell / Local Dev
Target: ARGUS Phase 2 Graph & Risk Infrastructure

---

## 1. Docker Status
Output of `docker ps --filter "name=argus-neo4j"`:
- **Container Name**: `argus-neo4j`
- **Image**: `neo4j:5-community`
- **Status**: Running (Up ~40 minutes)
- **Ports**: `0.0.0.0:7474->7474/tcp`, `0.0.0.0:7687->7687/tcp`

---

## 2. Neo4j Graph Queries
Executed via `cypher-shell` inside `argus-neo4j`:

### a) Total Node Count
Query: `MATCH (n) RETURN count(n);`
- **Count**: 369

### b) Node Label Distribution
Query: `MATCH (n) RETURN labels(n) AS labels, count(*) AS c ORDER BY c DESC;`
| Labels | Count |
|---|---|
| `["AWSEC2Subnet", "EC2Subnet", "Subnet"]` | 59 |
| `["IpPermissionInbound", "AWSEC2NetworkAclRule", "EC2NetworkAclRule"]` | 36 |
| `["AWSEC2NetworkAclRule", "EC2NetworkAclRule", "IpPermissionEgress"]` | 36 |
| `["AWSEC2Route", "EC2Route"]` | 36 |
| `["AWSEC2SecurityGroup", "EC2SecurityGroup", "NetworkAccessControl"]` | 18 |
| `["AWSIpPermissionInbound", "IpPermissionInbound", "IpRule", "AWSIpRule"]` | 18 |
| `["IpRule", "AWSIpRule"]` | 18 |
| `["AWSEC2NetworkAcl", "EC2NetworkAcl"]` | 18 |
| `["AWSVpc", "VirtualNetwork"]` | 18 |
| `["AWSCidrBlock", "AWSIpv4CidrBlock"]` | 18 |
| `["AWSEC2RouteTableAssociation", "EC2RouteTableAssociation"]` | 18 |
| `["AWSEC2RouteTable", "EC2RouteTable"]` | 18 |
| `["AWSInternetGateway"]` | 18 |
| `["AWSPolicyStatement"]` | 15 |
| `["AWSManagedPolicy", "AWSPolicy"]` | 6 |
| `["ModuleSyncMetadata", "SyncMetadata"]` | 4 |
| `["AWSPrincipal", "AWSUser", "UserAccount"]` | 3 |
| `["AWSPrincipal", "AWSServicePrincipal", "ServiceAccount"]` | 3 |
| `["AWSPrincipal", "AWSRole", "PermissionRole"]` | 3 |
| `["AWSAccountAccessKey", "AccountAccessKey", "APIKey"]` | 3 |
| `["AWSAccount", "Tenant"]` | 1 |
| `["AWSRootPrincipal", "AWSPrincipal"]` | 1 |
| `["AWSIpRange", "IpRange"]` | 1 |

### c) AWS Users
Query: `MATCH (u:AWSUser) RETURN u.name ORDER BY u.name;`
- `argus-cartography-scanner`
- `argus-cloudgoat-admin`
- `raynor-cgidjq6epnjtgc`

### d) CloudGoat Policies
Query: `MATCH (p:AWSPolicy) WHERE p.name STARTS WITH 'cg-' RETURN p.name;`
- `cg-raynor-policy-cgidjq6epnjtgc`

### e) S3 Bucket Count
Query: `MATCH (b:AWSS3Bucket) RETURN count(b);`
- **Count**: 0

### f) AWS Account Count
Query: `MATCH (a:AWSAccount) RETURN count(a);`
- **Count**: 1

---

## 3. AWS Identity
Query: `aws sts get-caller-identity --profile argus-scanner`
- **IAM User Name**: `argus-cartography-scanner` (last segment of ARN; account ID and ARN omitted)

---

## 4. Software Versions
*(Versions from `D:\argus\argus-venv\Scripts\python.exe`)*
- **Python**: `3.13.5`
- **pip**: `25.1.1`
- **cartography**: `0.141.0`
- **neo4j**: `6.3.1`
- **networkx**: `3.7`
- **numpy**: `2.5.3`
- **pytest**: `9.1.1`
- **Docker**: `29.4.0, build 9d7ad9f`
- **AWS CLI**: `2.37.4`
- **Git**: `2.50.1.windows.1`

---

## 5. Environment File (.env) Status
- **Exists**: `True`
- **Git-Ignored**: `True` (`.env` matches `.gitignore`)
- **NEO4J_PASSWORD**: Present
- **AWS_PROFILE**: Present
- **AWS_DEFAULT_REGION**: Present
*(Note: Values strictly omitted per security guidelines)*

---

## 6. Problems Found
1. **Cartography Module Sync Configuration**: `cartography.json` defines `"aws-requested-syncs": "iam,ec2,kms,s3,rds"`. In Cartography 0.141.0, the umbrella name `"ec2"` is rejected. Specific submodules must be specified instead (e.g. `ec2:security_group, ec2:subnet, ec2:vpc, ec2:network_acls, ec2:route_table, ec2:internet_gateway, ec2:vpc_endpoint`). In addition, executions require the `--selected-modules aws` flag to prevent Cartography from attempting Azure and other external cloud synchronizations.
2. **Missing Data Crown Jewels**: `AWSS3Bucket` count in Neo4j is `0`. Consequently, no sensitive storage data crown jewel exists yet in the attack graph. P1 needs to provision/ingest test buckets for data attack paths.
3. **Testbeds Path Ignored**: `testbeds/cloudgoat/ground_truth_paths.json` was matched by `.git/info/exclude` line 7 (`cloudgoat/`). Fixed by adding negation rules in `.gitignore`.
4. **Previous version report used wrong interpreter**: The initial preflight (before this correction) reported versions from `C:\Users\Supravati\anaconda3\python.exe` (networkx 3.4.2, numpy 2.4.3, pytest 8.3.4, pip 25.3) instead of the project venv `D:\argus\argus-venv` (networkx 3.7, numpy 2.5.3, pytest 9.1.1, pip 25.1.1). All versions now match `requirements.txt` pins.
