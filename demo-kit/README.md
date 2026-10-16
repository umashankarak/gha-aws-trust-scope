# Demonstration kit: any-branch trust versus main-only trust

This kit reproduces the owned-infrastructure demonstration in the paper. It creates two
IAM roles in **your own** AWS account, both trusted only by **your own** GitHub repository,
and neither with any permissions attached:

| Role | Trust (subject condition) | Code |
|---|---|---|
| `oidc-demo-any-branch` | `StringLike` `repo:OWNER/REPO:*` | S2 |
| `oidc-demo-main-only`  | `StringEquals` `repo:OWNER/REPO:ref:refs/heads/main` | S3 |

A workflow in the repository requests a GitHub OIDC token, prints only its `sub` claim, and
calls `sts:AssumeRoleWithWebIdentity` for each role. A push to `main` should obtain
credentials from both roles; a push of a new, unreviewed branch should obtain credentials from
the any-branch role and be refused by the main-only role.

Use this kit only with an AWS account and a GitHub repository that you own. It needs the AWS
CLI (configured for your account), git, Python 3 and bash. It takes under an hour and costs
nothing at this scale.

## 1. Create a test repository

On github.com create a new **private** repository (for example `oidc-branch-demo`) with a
README. Private keeps your AWS account ID, which appears in the workflow file, out of public
view. Then:

```bash
git clone https://github.com/OWNER/oidc-branch-demo.git
cd oidc-branch-demo
/path/to/demo-kit/pretest.sh OWNER oidc-branch-demo     # read-only checks; every line should say [ OK ]
```

## 2. Create the two roles and the workflow

```bash
/path/to/demo-kit/setup.sh OWNER oidc-branch-demo
cp /path/to/demo-kit/template/README-repo.md README.md
```

`setup.sh` creates the GitHub OIDC provider in your account if none exists, creates both roles,
and writes `.github/workflows/oidc-demo.yml` with the role ARNs filled in.

## 3. Match the subject format GitHub issues for your repository

Repositories created or renamed on github.com after 15 July 2026 receive the immutable subject
format `repo:OWNER@OWNER_ID/REPO@REPO_ID:...`, which a name-only trust does not match. Push once
to `main` and open the run summary (Actions → oidc-demo):

```bash
git add . && git commit -m "Add OIDC demo workflow" && git push origin main
```

* If both roles were **assumed**, your repository uses the classic format; go to step 4.
* If both were **refused** and the `token sub` column shows `repo:OWNER@.../REPO@...`, copy the
  part before `:ref:` and run:

  ```bash
  /path/to/demo-kit/use-immutable-subject.sh 'repo:OWNER@OWNER_ID/REPO@REPO_ID'
  git commit --allow-empty -m "Rerun after trust update" && git push origin main
  ```

  Both roles should now be assumed. (This is runs 1 to 3 in the paper.)

## 4. Push an unreviewed branch

```bash
git checkout -b feature/unreviewed-change
echo "test" > note.txt
git add note.txt && git commit -m "Change on a new branch, no review"
git push origin feature/unreviewed-change
```

Expected in the run summary: `oidc-demo-any-branch` **assumed**, `oidc-demo-main-only`
**refused**. (Run 4 in the paper.)

## 5. Collect the CloudTrail record

Wait about 15 minutes for CloudTrail, then run from the repository folder:

```bash
/path/to/demo-kit/evidence.sh
```

It saves `evidence/cloudtrail-raw.json` (the full export, which contains your account ID; keep
it private) and `evidence/cloudtrail-summary.json`, and prints one line per attempt. Refused
`AssumeRoleWithWebIdentity` events do not record the target role, so the summary lists every
demo attempt by token subject and time.

## 6. Tear down

```bash
/path/to/demo-kit/teardown.sh
```

Deletes both roles, and the OIDC provider only if `setup.sh` created it. You can then delete the
test repository.

## Notes

* The workflow never prints or stores the token itself, only its `sub` claim.
* `evidence/cloudtrail-redacted.json` at the top of this repository is the author's record of
  these steps, with the AWS account ID replaced by `ACCOUNT_ID`.
