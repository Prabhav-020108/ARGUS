# Mutation Engine (Phase 1 skeleton)

Takes a known-good Terraform config (`fixtures/*.tf`) and breaks it exactly
one way per mutator. The original, un-mutated file is the reference fix —
zero manual labeling effort.

- `mutators.py` — the `Mutator` class and the registered `MUTATORS` list.
- `fixtures/` — known-good `.tf` files each mutator operates on.
- `test_mutators.py` — round-trip test per mutator (mutate → fix → identical to original).

## Run the tests

From the repo root:

    pytest ml/mutation_engine/test_mutators.py -v

## Add a new mutator

1. If it targets a new resource type, add a new known-good fixture under `fixtures/`.
2. Add a `Mutator(...)` entry to `MUTATORS` in `mutators.py`, picking a
   `good_value` string that appears **exactly once** in its fixture file.
3. `pytest` will pick it up automatically — no test code to write per mutator.

This will be expanded in Phase 5 to cover every rule in both Rego libraries
(Phase 4) and generate the full training dataset for M1/M2.
