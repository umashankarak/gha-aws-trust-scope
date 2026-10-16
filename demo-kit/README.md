# OIDC branch demo kit (Paper 10)

Shows, in your own AWS account, that a role trusting `repo:OWNER/REPO:*` (S2) can
be assumed from a brand-new, unreviewed branch, while a role pinned to `main` (S3)
refuses the same branch. The roles have NO permissions; assuming them is the test.
About one hour; no cost at this scale.

Replace `YOUR_GITHUB_USER` below with your GitHub username.

## 1. Create the repository on github.com (2 min)
New repository → name `oidc-branch-demo` → **Private** → check "Add a README file" → Create.
Private keeps your AWS account ID out of public view. Private repos get free Actions minutes; this test uses a few.

## 2. Clone it and run the pre-test (2 min)
```bash
cd ~/Documents/EB1A/paper10/experiment
tar -xzf oidc-demo-kit.tar.gz          # creates oidc-demo-kit/
git clone https://github.com/YOUR_GITHUB_USER/oidc-branch-demo.git
cd oidc-branch-demo
../oidc-demo-kit/pretest.sh YOUR_GITHUB_USER oidc-branch-demo
```
Every line should say `[ OK ]`. It creates nothing.

## 3. Create the two test roles (1 min)
```bash
../oidc-demo-kit/setup.sh YOUR_GITHUB_USER oidc-branch-demo
cp ../oidc-demo-kit/template/README-repo.md README.md
```
This creates the roles (and the GitHub OIDC provider if your account has none)
and writes `.github/workflows/oidc-demo.yml` with the role ARNs filled in.

## 4. Run 1: push to main (expected: A allowed, B allowed)
```bash
git add .
git commit -m "Add OIDC demo workflow"
git push origin main
```
Open the repo on github.com → Actions → the "oidc-demo" run → the summary table.

## 5. Run 2: push an unreviewed branch (expected: A ALLOWED, B DENIED)
```bash
git checkout -b feature/unreviewed-change
echo "test" > note.txt
git add note.txt
git commit -m "Change on a new branch, no review"
git push origin feature/unreviewed-change
```
Check the new run's summary. Take a screenshot of both summary tables.

## 6. Collect CloudTrail evidence (wait ~15 minutes after run 2)
```bash
../oidc-demo-kit/evidence.sh
```
Prints one line per attempt (time, role, ALLOWED/DENIED, branch subject) and saves
`evidence/cloudtrail-raw.json` and `evidence/cloudtrail-summary.json`.
Copy the `evidence/` folder to `../oidc-scope/data/owned-infra/` and paste the printed table to Claude.

## 7. Tear down (1 min)
```bash
../oidc-demo-kit/teardown.sh
```
Deletes both roles, and the OIDC provider only if step 3 created it. You can then
delete the GitHub repository (Settings → Delete), or keep it private as evidence.

## Notes
- The workflow prints only the token's `sub` claim, never the token.
- Results that differ from "expected" are still results: paste them to Claude as they are.
