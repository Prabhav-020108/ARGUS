# ARGUS
*Privacy-First, Tiered-Remediation Cloud Attack-Graph Platform*

RVCE III Semester Experiential Learning — CS Cluster (Cloud Security Theme)

## What this is
See `docs/ARGUS_v3_Tiered_Privacy_First_Remediation.md` for the full design
and `docs/ARGUS_Master_Execution_Guide_v3.docx` for the phase-by-phase build plan.

## Team & roles
| Role | Name | Owns |
|---|---|---|
| A — Graph & Prioritization | TBD | Cartography, PageRank, interdiction MILP |
| B — Privacy & Verification | TBD | Privacy airlock, Rego policies, verification gate |
| C — ML Engineer | TBD | Mutation engine, M1/M2 training, tiered pipeline |
| D — DPDP, Research & Backend/Dashboard | TBD | DPDP mapping, paper, FastAPI, React dashboard |

## Local setup
1. Install Docker Desktop, Python 3.11+, Node 20+, Git.
2. `Copy-Item .env.example .env`
3. `docker compose up`
4. Open http://localhost:7474 to confirm Neo4j is running.

## Repo structure
See the folder-by-folder READMEs, or `docs/ARGUS_Master_Execution_Guide_v3.docx` → Shared Contracts → Repository Structure.