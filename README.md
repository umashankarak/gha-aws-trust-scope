# gha-aws-trust-scope

Code, codebook and data for the paper

> Kalaiah U. *Repository-level trust, branch-level gaps: A measurement study of GitHub Actions
> access to Amazon Web Services in public infrastructure code.* Submitted to PLOS ONE, 2026.

The study collected public Terraform, CloudFormation and AWS CDK files that define an AWS IAM
trust for the GitHub Actions OIDC issuer, graded each trust on who can assume the role (S0 to S4)
and what the role can do (P0 to P3), validated the classifier against blind human labels, and
corrected the prevalence estimates for the measured classifier error.

## Contents

| Path | What it is |
|---|---|
| `CODEBOOK.md` | Codebook v2: the trust-scope and permission-breadth codes and rules 1-7 (S1 Appendix) |
| `VERSION` | Classifier version (v2.2, frozen 12 October 2026) |
| `src/` | Collection, deployedness filter, classifier, permission resolver, labeling, scoring, error correction and analysis scripts |
| `tests/`, `fixtures/` | Hand-coded fixtures and regression tests for the classifier |
| `data/coded_resolved.csv` | All 6,716 candidate files with filter verdicts, trust code and permission code (identifiers hashed) |
| `data/label_sample.csv`, `data/label_holdout_sample.csv` | Development and held-out samples, with strata |
| `data/labels_pass1.csv`, `data/labels_holdout.csv` | The author's blind labels (development round, held-out round) |
| `data/S1_Table_holdout_disagreements.csv` | Held-out files where classifier and author disagreed (S1 Table) |
| `data/corrected_estimates.csv` | Raw and error-corrected estimates with 95% bootstrap intervals |
| `data/analysis_extra.txt` | Funnel, sensitivity analyses and cross-tabs |
| `evidence/` | Owned-infrastructure demonstration: redacted CloudTrail events, workflow file, checksums (S2 File) |
| `demo-kit/` | Scripts that reproduce the demonstration in your own AWS account and GitHub repository |

## Identifiers are hashed

The paper reports results in aggregate and does not name repositories with loose or broad
configurations. Repository names, file paths and file keys are therefore replaced by salted
HMAC-SHA256 hashes (the salt is not published). The same hash is used in every file, so the
tables still join. The downloaded source files themselves are not redistributed. Free-text columns
(classifier reasons, matched subject patterns, permission evidence, labeling notes) are omitted
because they can quote repository names. The AWS account ID in the demonstration evidence is
replaced by `ACCOUNT_ID`.

## Reproducing the reported numbers

Python 3.9 or newer; no third-party packages are needed for these steps.

```bash
python3 src/verify_numbers.py                 # checks every figure in the paper against data/
python3 src/correct_estimates.py --out data/  # recomputes the error-corrected estimates (fixed seed)
python3 src/score_labels.py --out data/ --labels data/labels_holdout.csv --sample label_holdout_sample.csv
python3 tests/run.py                          # classifier against the hand-coded fixtures
```

`analysis_extra.py` and the classifier itself need the original source files, which are not
included. To rebuild a comparable sample from scratch, create a GitHub token with read-only access
to public repositories and run:

```bash
export GITHUB_TOKEN=...
python3 src/collect.py --out data_new/
python3 src/pipeline.py --out data_new/
```

Code search results change over time, so a new collection will not match the 28-29 September 2026
snapshot exactly.

## Demonstration kit

`demo-kit/` reproduces the owned-infrastructure test: two IAM roles with no permissions, one
trusting every branch of a repository and one trusting only `main`, and a workflow that tries to
assume both. Use it only with an AWS account and a GitHub repository that you own. See
`demo-kit/README.md`.

## Licenses

Code: MIT (see `LICENSE`). Data and codebook: CC BY 4.0 (see `DATA_LICENSE.md`).

## Contact

Umashankara Kalaiah, umashankarak@gmail.com
