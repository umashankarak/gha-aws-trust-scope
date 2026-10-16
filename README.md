# gha-aws-trust-scope

Code, codebook and data for the paper

> Kalaiah U. *Repository-level trust, branch-level gaps: A measurement study of GitHub Actions
> access to Amazon Web Services in public infrastructure code.* Submitted to PLOS ONE, 2026.

The study collected public Terraform, CloudFormation and AWS CDK files that define an AWS IAM
trust for the GitHub Actions OIDC issuer (`token.actions.githubusercontent.com`), graded each
trust on who can assume the role (S0 to S4) and what the role can do (P0 to P3), validated the
classifier against blind human labels, and corrected the prevalence estimates for the measured
classifier error. Every number in the paper can be recomputed from the files here.

## Quick start: check the paper's numbers (about one minute)

Requires Python 3.9 or newer. No third-party packages are needed. Run from the repository root.

```bash
python3 tests/run_all.py
python3 src/verify_numbers.py
python3 src/correct_estimates.py --out data/
python3 src/score_labels.py --out data/ --labels data/labels_holdout.csv --sample label_holdout_sample.csv
```

Expected results:

| Command | Expected output |
|---|---|
| `tests/run_all.py` | `ALL SUITES PASS` |
| `src/verify_numbers.py` | one `[OK]` line per figure in the paper, ending `0 mismatch(es)` |
| `src/correct_estimates.py` | S2 x P3 corrected 21.0% [11.6%, 31.0%]; loose x broad 25.1% [14.0%, 36.8%]; loose share 40.2% [23.8%, 54.6%] (fixed seed, so identical on every run) |
| `src/score_labels.py` | trust: kappa 0.710, weighted accuracy 0.802; breadth: kappa 0.689, weighted accuracy 0.832 |

`correct_estimates.py` rewrites `data/corrected_estimates.csv` with identical values, and
`score_labels.py` writes `data/label_disagreements_holdout.csv` (the same rows as
`data/S1_Table_holdout_disagreements.csv`).

## Where each item in the paper comes from

| Paper item | File(s) | Script |
|---|---|---|
| Table 3, Fig 2 (funnel) | `data/coded_resolved.csv` | `verify_numbers.py` |
| Table 4 (trust scope, raw and corrected) | `data/coded_resolved.csv`, `data/corrected_estimates.csv` | `correct_estimates.py` |
| Table 5, Fig 3 (trust x breadth) | `data/coded_resolved.csv` | `verify_numbers.py` |
| Table 6 (headline measures) | `data/corrected_estimates.csv` | `correct_estimates.py` |
| Tables 7 to 9 (agreement) | `data/label_holdout_sample.csv`, `data/labels_holdout.csv` | `score_labels.py` |
| Table 10 (sensitivity) | `data/analysis_extra.txt` | `analysis_extra.py` (needs source files, see below) |
| Table 11 (demonstration) | `evidence/cloudtrail-redacted.json` | `demo-kit/` |
| S1 Appendix (codebook) | `CODEBOOK.md` | |
| S1 Table (held-out disagreements) | `data/S1_Table_holdout_disagreements.csv` | `score_labels.py` |
| S1 File (this archive) | this repository, release v1.0 | |
| S2 File (demonstration evidence) | `evidence/` | `demo-kit/evidence.sh` |

## Repository layout

| Path | Contents |
|---|---|
| `CODEBOOK.md` | Codebook v2: trust-scope codes S0 to S4, U1, U3; permission codes P0 to P3, PU2; rules 1 to 7; changes from v1 |
| `VERSION` | Classifier version 2.2, frozen on 12 October 2026 before held-out labeling |
| `src/` | Collection (`collect.py`, `gh.py`), deployedness filter (`deployedness.py`), trust classifier (`classify.py`), permission resolver (`permissions.py`, `resolve_permissions.py`), pipeline (`pipeline.py`), labeling page generator (`make_label_sheet.py`), scoring (`score_labels.py`, `diagnose_disagreements.py`), error correction (`correct_estimates.py`), sensitivity analyses (`analysis_extra.py`), number check (`verify_numbers.py`) |
| `tests/`, `fixtures/` | Hand-coded example trust policies and regression tests for the classifier and filter |
| `data/` | Coded dataset, samples, human labels and outputs (identifiers hashed; see below) |
| `evidence/` | Demonstration record: redacted CloudTrail events, the workflow that was run, checksums of the unredacted originals |
| `demo-kit/` | Scripts to repeat the demonstration in your own AWS account and GitHub repository |

## Data dictionary

`data/coded_resolved.csv`: one row per candidate file found by code search (6,716 rows).

| Column | Meaning |
|---|---|
| `key` | Hashed file identifier; joins to the sample and label files |
| `repo` | Hashed repository identifier (files from the same repository share it) |
| `path` | Hashed file path; the original file extension is kept |
| `frame`, `shard` | Search frame (file type) and file-size band that found the file |
| `kept` | `True` if the file passed the deployedness filter (806 files) |
| `kept_strict` | `True` if the repository met all four deployment signals |
| `exclusions` | Hard-exclusion reasons, separated by `;` (empty if none) |
| `signals_passed` | Number of the four deployment signals the repository met |
| `rung` | Trust-scope code: S0 to S4, U1, U3, or PARSE_ERROR |
| `aud_constrained` | `True` if the trust also checks the `aud` claim |
| `sub_format` | Form of the subject patterns: `historical` (owner/repo names), `immutable` (contains `@`), `mixed`, or `none` |
| `perm_breadth` | Permission code from the trust file alone |
| `perm_breadth_final` | Permission code after explicit cross-file links (used in the paper): P0 to P3, PU2 |
| `perm_source` | `same-file`, `cross-file` or `unresolved` |

Sample and label files:

| File | Columns |
|---|---|
| `label_sample.csv` | Development-round sample (167 files): `key`, `repo`, `path`, `stratum` (classifier code used for stratification), `stratum_size` (kept files in that stratum) |
| `label_holdout_sample.csv` | Held-out sample (50 files), same columns |
| `labels_pass1.csv` | Author's blind labels for the development round (codebook v1): `key`, `human_rung`, `human_breadth` |
| `labels_holdout.csv` | Author's blind labels for the held-out round (codebook v2), same columns |
| `S1_Table_holdout_disagreements.csv` | Held-out files where classifier and author disagree: classifier and author codes on both axes |
| `corrected_estimates.csv` | `measure`, `raw`, `corrected`, `ci_low`, `ci_high` (95% bootstrap interval, 5,000 replicates, seed 20261012) |
| `analysis_extra.txt` | Funnel, `StringEquals` check, rule 5 sensitivity, single-role subset and cross-tabs |

`N/A` in the `human_breadth` column of a label file marks files that are not AWS GitHub trusts (U3).

## What is not included, and why

The paper reports results in aggregate and does not name any repository with a loose or broad
configuration. For that reason:

* the 6,716 downloaded source files are not redistributed;
* repository names, file paths and file keys are replaced by salted HMAC-SHA256 hashes (the
  salt is withheld), consistently across all files so the tables still join;
* free-text columns that can quote repository names (classifier reasons, matched subject
  patterns, permission evidence, labeling notes) are omitted;
* a few test fixtures derived from real files have had owner names and AWS account numbers
  replaced with placeholders;
* the AWS account ID in the demonstration evidence is replaced by `ACCOUNT_ID`.

Steps that need the original files (`analysis_extra.py`, re-running `classify.py` on the
sample) cannot be run from this repository; their outputs are included. Researchers who need
the underlying file list for verification can contact the author.

## Collecting a new sample

The collection is reproducible in method but not in content: code search results change over
time, so a new run will not match the 28 to 29 September 2026 snapshot. With a GitHub token that
has read-only access to public repositories (no scopes needed):

```bash
export GITHUB_TOKEN=...
python3 src/collect.py --out data_new/
python3 src/pipeline.py --out data_new/
python3 src/resolve_permissions.py --out data_new/
```

Optional: `pip install pyyaml` enables the CloudFormation YAML parser.

## Demonstration

`demo-kit/README.md` repeats the owned-infrastructure test: one role trusting every branch of a
repository, one trusting only `main`, and a workflow that tries both from `main` and from a new,
unreviewed branch. Use it only with an AWS account and a GitHub repository that you own.

## Re-running the collection: what to expect

The numbers in the paper come from a snapshot taken on 28 and 29 September 2026. A new run of
`collect.py` and `pipeline.py` will not return the same files: repositories are deleted, renamed
or made private, files are edited, new repositories appear, and GitHub's code-search index
changes. Expect different counts and similar proportions. The paper's estimates are checked
against the frozen snapshot, which is what `data/coded_resolved.csv` contains, and every reported
figure can be recomputed from it with `src/verify_numbers.py`.

The original files and the unhashed repository list are not published, because doing so would
identify roles that can be assumed from any branch or any repository. Editors and reviewers who
need them to check individual classifications can request them from the author; they will be
shared privately and not redistributed.

## Licenses

Code: MIT (`LICENSE`). Data, evidence and codebook: CC BY 4.0 (`DATA_LICENSE.md`).

## Citation and contact

Please cite the paper above. Umashankara Kalaiah, umashankarak@gmail.com
