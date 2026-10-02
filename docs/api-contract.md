# FastAPI ↔ Dashboard Contract

**Status: PROPOSED - pending Role D confirmation against the dashboard mock data (iamNodes / iamEdges).**

Every backend endpoint (built in Phase 7) must return data in the exact
shape the dashboard expects (object names: `iamNodes` / `iamEdges`,
`iamFindings`, `iamComp`, `iamRem`). Freeze the exact field names here
once the dashboard's mock data shape exists (Phase 8), and add every new
endpoint to the shared Postman collection ("ARGUS API" workspace) the
same day it's built.

## Risk graph shape (Phase 2)

Node risk score is computed as `risk = to_percent(score_digraph(G))`.

```json
{
  "nodes": [{"id": "arn:...", "label": "raynor-...", "kind": "user", "risk": 87.3, "isEntry": true, "isCrownJewel": false}],
  "edges": [{"source": "arn:...", "target": "ADMIN_EQUIV", "etype": "CAN_ESCALATE", "p": 0.85}]
}
```