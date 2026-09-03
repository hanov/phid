# Contributing to PHI/PII Security CLI

The project uses [PolyForm Noncommercial 1.0.0](LICENSE) with separate commercial
agreements. Contributions must support the Python CLI, read-only AWS boundary,
local inference and evidence-based assessment. Do not submit real patient data,
credentials, private account logs, unlicensed code or model weights.

## Contributor agreement

For contributions you intentionally submit for inclusion, you grant Oleksandr
Amirkhanov a perpetual, worldwide, non-exclusive, royalty-free, irrevocable
copyright license to reproduce, modify, prepare derivative works, display,
perform, distribute and sublicense your contribution, including under commercial
terms. You retain ownership of your contribution.

You also grant a perpetual, worldwide, non-exclusive, royalty-free patent license,
with the right to sublicense to recipients, under claims you control necessarily
infringed by your contribution alone or combined with the project as submitted,
to make, have made, use, offer to sell, sell, import and otherwise transfer that
contribution and combination. No unrelated patent or trademark rights are granted.

You represent that you have authority to make these grants, including necessary
employer permission, and identify third-party material and its applicable terms.
Do not submit material whose terms prevent these grants. Contributions are
provided as is, without additional support obligations, to the extent allowed by
law. Acceptance does not require the maintainer to include or retain a change.

## Explicit acceptance

Before a contribution is merged, the contributor must include this statement in
the pull request or a signed written submission identifying the contribution:

> I have read and agree to the contributor agreement in CONTRIBUTING.md for
> PHI/PII Security CLI. I have authority to grant these rights, including any
> required employer authorization, and have identified included third-party material.

Include your name and submission date. For employer-owned work, identify the
employer and confirm authorization; arrange private written authorization if
needed. The maintainer must retain the acceptance and exact agreement revision
with the contribution record. No CLA bot or automated acceptance is claimed.
Previously submitted material is not retroactively covered without agreement.

## Development

Discuss substantial changes with the maintainer, use synthetic test fixtures,
explain behavior and validation, and run:

```sh
python3 -m unittest discover -s tests_python -v
```

Preserve third-party notices and report dependency/model-license changes.
Commercial licenses cover project rights only; do not assume they relicense
third-party libraries or weights. Contribution grants enable the maintainer's
commercial licensing and paid services without transferring your ownership.
