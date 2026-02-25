# Serialization compatibility tests

The contracts include golden tests that serialize public-facing `#[contracttype]` structs/enums and event payloads to XDR and compare against committed hex outputs.

This catches accidental breaking changes to type layouts that would impact SDKs, indexers, or other external tooling.

## Updating goldens

When you intentionally change a public type/event layout:

1. Regenerate the golden files:
   - `python3 contracts/scripts/gen_serialization_goldens.py`
2. Review the diff and ensure the changes are expected.
3. Commit the updated golden files together with the intentional layout change.

