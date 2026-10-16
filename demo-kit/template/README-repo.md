# oidc-branch-demo

Test repository for a research demonstration. Its only content is a GitHub
Actions workflow that requests a GitHub OIDC token and tries to assume two AWS
IAM roles in the owner's own account:

- Role A trusts `repo:<owner>/<repo>:*` (any branch of this repository).
- Role B trusts `repo:<owner>/<repo>:ref:refs/heads/main` only.

Neither role has any permissions. The roles are deleted after the test.
