# Phase 2 Validation Report

**Date:** 2026-10-02  
**Target Environment:** Local CloudGoat `iam_privesc_by_rollback` in AWS Free Tier scanned into Neo4j  
**Branch:** `phase2/config-validation`  

---

## 1. Graph Size & Diagnostics

- **Node count:** 15
- **Edge count:** 9

### Edges by etype
| Relationship Type | Count |
| :--- | :--- |
| `CAN_ESCALATE` | 1 |
| `DIRECT_ADMIN` | 1 |
| `HAS_POLICY` | 2 |
| `HAS_STATEMENT` | 2 |
| `USES_KEY` | 3 |

### Resolved Entry Nodes
- `INTERNET` (kind: internet)
- `****GRUI` (kind: key, active key for `raynor-cgidjq6epnjtgc`)

### Crown Jewels
- `ADMIN_EQUIV` (kind: admin)

---

## 2. Top-15 Ranked Nodes (Personalized PageRank)

Personalized vector $e_S$ seeded uniformly across resolved entry nodes (`INTERNET` and `****GRUI`).

| Rank | Score | Kind | Label |
| :--- | :--- | :--- | :--- |
| 1 | 0.17506 | internet | `INTERNET` |
| 2 | 0.17506 | key | `****GRUI` |
| 3 | 0.13392 | user | `raynor-cgidjq6epnjtgc` |
| 4 | 0.11384 | policy | `cg-raynor-policy-cgidjq6epnjtgc` |
| 5 | 0.09676 | stmt | `IAMPrivilegeEscalationByRollback` |
| 6 | 0.06991 | admin | `ADMIN_EQUIV` |
| 7 | 0.00000 | user | `argus-cartography-scanner` |
| 8 | 0.00000 | user | `argus-cloudgoat-admin` |
| 9 | 0.00000 | role | `AWSServiceRoleForResourceExplorer` |
| 10 | 0.00000 | role | `AWSServiceRoleForSupport` |
| 11 | 0.00000 | role | `AWSServiceRoleForTrustedAdvisor` |
| 12 | 0.00000 | key | `****NE4T` |
| 13 | 0.00000 | key | `****YZXH` |
| 14 | 0.00000 | policy | `AdministratorAccess` |
| 15 | 0.00000 | stmt | `arn:aws:iam::aws:policy/AdministratorAccess/statement/1` |

---

## 3. Discovered Attack Paths

### Path from Entry to Crown Jewel
- **Path from key entry `****GRUI`:**
  `****GRUI` $\rightarrow$ `raynor-cgidjq6epnjtgc` $\rightarrow$ `cg-raynor-policy-cgidjq6epnjtgc` $\rightarrow$ `IAMPrivilegeEscalationByRollback` $\rightarrow$ `ADMIN_EQUIV`  
  - **Path cumulative probability ($\prod p$):** `0.76500`

---

## 4. Acceptance Criteria Evaluation

- **Check (a) [FAIL]:** `ADMIN_EQUIV` in top 3 by score.
  - Literal rank: **6**
  - Rank excluding entry nodes and `INTERNET`: **4** (target: $\le 3$).
  - *Root Cause Analysis:* The attack chain is a strictly feed-forward 4-hop chain (`key` $\rightarrow$ `user` $\rightarrow$ `policy` $\rightarrow$ `statement` $\rightarrow$ `ADMIN_EQUIV`). Under Personalized PageRank with damping factor $\alpha = 0.85$ and edge probabilities $\le 1.0$, score decays at each hop ($\pi_{v} = \alpha \cdot p_{uv} \cdot \pi_u$). Consequently, `user` (rank 1 non-entry), `policy` (rank 2 non-entry), and `statement` (rank 3 non-entry) precede `ADMIN_EQUIV` (rank 4 non-entry).
- **Check (b) [PASS]:** Path matches ground truth ignoring key nodes.
  - Expected: `raynor-cgidjq6epnjtgc` $\rightarrow$ `cg-raynor-policy-cgidjq6epnjtgc` $\rightarrow$ `<statement containing iam:SetDefaultPolicyVersion>` $\rightarrow$ `ADMIN_EQUIV`
  - Actual: `raynor-cgidjq6epnjtgc` $\rightarrow$ `cg-raynor-policy-cgidjq6epnjtgc` $\rightarrow$ `IAMPrivilegeEscalationByRollback` $\rightarrow$ `ADMIN_EQUIV`
- **Check (c) [PASS]:** Scanner control principal has NO path to `ADMIN_EQUIV`.
  - Principal `argus-cartography-scanner` and its active access key `****YZXH` have no outgoing edges leading to `ADMIN_EQUIV` (PageRank score = `0.00000`).

---

## 5. Known Limitations Observed

1. **No World-Open Inbound Network Rules:** In the deployed CloudGoat `iam_privesc_by_rollback` scenario, security groups do not expose any public inbound rules (0.0.0.0/0 or ::/0). As a result, the `INTERNET` node has no outgoing edges to security groups or compute instances, remaining an isolated entry sink.
2. **S3 Bucket Tags Omitted by Cartography:** AWS S3 bucket tags (such as `contains_personal_data=true`) applied via `put-bucket-tagging` are not stored as Neo4j node properties or `AWSTag` relationships by Cartography 0.141.0. Crown jewel buckets must rely on explicit naming in `config.json` (`crown_jewel_ids`).
3. **Linear Chain Score Decay in PPR:** In pure linear directed paths with no convergence or cycles, Personalized PageRank attenuates with each hop ($\le 0.85\times$ per hop). Target crown jewels situated at the end of multi-hop chains naturally receive lower raw stationary probabilities than the intermediate staging nodes directly reachable from entry points.
