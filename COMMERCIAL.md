# Commercial licensing — PHI/PII Security CLI

PHI/PII Security CLI (`phi-security`, command `phi-sec`) is source-available under
[PolyForm Noncommercial 1.0.0](LICENSE). It is not OSI-approved Open Source.
This page summarizes the licensing model; LICENSE controls the public grant.

## When a separate agreement is needed

If your proposed use is outside the purposes permitted by LICENSE, obtain a
signed commercial agreement from **Oleksandr Amirkhanov** before that use.
Examples include commercial internal AWS security assessments, managed security
services, paid customer investigations, distributing a commercial derivative,
and bundling this tool into an OEM or reseller offering.

A CLI-only deployment, internal modification, or private fork does not by itself
make a commercial purpose noncommercial. Paying a consultant does not itself
supply a software license. A consultant's and customer's activities must each
be covered by the public license or an appropriate commercial agreement.

**Express public-license permissions still apply.** In particular, LICENSE
permits use by the organizations described in its Noncommercial Organizations
section, including health organizations, regardless of funding source. Do not
assume every healthcare deployment requires a paid license. Distribution,
modification, and notices remain subject to the actual license text. This page
neither narrows those permissions nor grants additional ones.

## Available agreement scopes

| Scope | Terms to specify in the signed order |
|---|---|
| Internal assessment | Licensee, affiliates, authorized operators, AWS accounts, term |
| Enterprise | Organization-wide scope, subsidiaries, deployment limits, support |
| Consulting / managed security | Authorized customer accounts, operators, reporting rights |
| OEM / redistribution | Products, versions, permitted modifications, recipients, notices |
| Reseller | Territories, channels, sublicensing authority, end-user terms |

The current product is a Python CLI, not a hosted service. Commercial rights to
build or operate an integration do not imply that hosting features are supplied.
No pricing, SLA, warranty, indemnity, redistribution, trademark, or reseller
rights are promised unless included in the executed agreement.

## Requesting a license

Contact **Oleksandr Amirkhanov** at [license@amirkhanov.org](mailto:license@amirkhanov.org).
Request a commercial-licensing conversation and provide:

1. Organization/legal entity and intended use.
2. Internal use versus client services, embedding, or redistribution.
3. Number of operators, AWS accounts, affiliates, and customer deployments.
4. Requested term and any support, training, customization, or integration needs.

Do not include credentials, patient records, raw logs, account evidence, or other
sensitive material in a public inquiry. The maintainer supplies the order details
and signature process privately. A request, quotation, download, or repository
contribution does not itself grant a commercial license.

See [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) for the negotiation form.
Consulting, implementation, customization and support may be contracted
separately. Their availability does not change the public license.

## Ownership, dependencies and data

The licensor retains rights in original project material; contributors retain
rights in their contributions and provide the grants in CONTRIBUTING.md.
The copyright holder may license its material commercially and provide paid
services. This licensing model does not prohibit those activities.

Dependency packages, optional database/NLP/inference libraries, Python, Ollama,
and model weights keep their own licenses. Commercial rights to this tool do
not grant rights to those components. Review the versions and model weights
actually distributed with any binary/container or commercial bundle.

Your AWS data and independently generated scan results are not relicensed as
project source code. Any project code or HTML template included in an exported
artifact remains subject to its applicable license. No trademark rights or
endorsement by AWS, Ollama, or other referenced vendors are granted.
