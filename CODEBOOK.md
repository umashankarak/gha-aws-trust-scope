# Codebook v2 (2026-10-11)

This codebook defines the two labels the classifier assigns and the human rater
assigns in validation. v2 replaces v1 after the pass-1 development round (167
items, labeled blind 2026-10-09 to 2026-10-11). The changes are listed at the
end. The held-out validation sample is labeled with v2 only.

## Unit of analysis

One file that defines (or is matched as defining) an AWS IAM trust for the
GitHub Actions OIDC provider `token.actions.githubusercontent.com`. When a file
defines several roles or several subject patterns, the file gets the LOOSEST
trust rung and the BROADEST permission of its GitHub-trusted roles.

## Axis 1: trust rung (who can assume the role)

| Code | Meaning | Examples |
|---|---|---|
| S0 | Anyone on GitHub | no `sub` condition; `repo:*`; owner prefix wildcard `repo:acme*/x` |
| S1 | Any repo in one org | `repo:acme/*`, `repo:acme/web-*` |
| S2 | One repo, any branch or tag | `repo:acme/web:*`; any `*` in the ref or environment: `ref:refs/heads/*`, `ref:refs/tags/v*`, `environment:*`, `environment:prod-*` |
| S3 | One repo + a literal ref or pull_request | `repo:acme/web:ref:refs/heads/main`, `repo:acme/web:pull_request` |
| S4 | One repo + a literal environment, or a pinned workflow | `repo:acme/web:environment:prod`; `job_workflow_ref` pinned at a literal ref |
| U1 | GitHub trust, but the subject's shape is not in the file | bare variable or parameter with no default; subject built by a function |
| U3 | Not an AWS IAM trust for GitHub Actions | Azure federated credentials, GCP workload identity, token-verification code, tests, module calls that only pass subjects, provider-only files |

Rules:

1. **Resolve from the same file.** A subject written as a local, a variable or
   parameter default, `format()`, `concat()`, a ternary, `Fn::Sub`, `!Sub`,
   `!If`, or a CDK template literal is resolved from the same file. Placeholders
   (`${var.org}`, `${GitHubOrg}`, `<ORGANISATION_NAME>`) in the owner/repo
   position count as named values. U1 only when nothing in the file gives the
   shape. A sub condition that cannot be read is never S0.
2. **Wildcards in the ref or environment give S2.** Anyone with write access to
   the repository can push a branch or tag matching a wildcard ref. For
   environments, GitHub's documentation states that "running a workflow that
   references an environment that does not exist will create an environment
   with the referenced name," that such an environment "will not have any
   protection rules or secrets configured," and that "anyone that can edit
   workflows in the repository can create environments via a workflow file"
   ([GitHub Docs: Managing environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)).
   So only a literal ref (S3) or literal environment name (S4) narrows the
   admitted set beyond the repository.
3. **Owner/repo wildcards.** A wildcard anywhere in the owner admits any
   organization whose name matches, and anyone can register a GitHub
   organization: S0. A wildcard in the repo name admits unnamed repos in that
   org: S1. A wildcard on the owner or repo caps the rung whatever follows
   (`repo:acme/*:environment:prod` is S1). In immutable subjects
   (`owner@123/repo@456`), `@<id>` and `@*` are IDs and do not widen the name.
4. **Scope.** Only AWS IAM trust policies for the GitHub Actions issuer count.
Note: **unresolvable patterns** in a multi-pattern condition are left out of the
   loosest-wins rule. That can only make the reported rung tighter than the
   truth, so the reported prevalence of loose trust is a lower bound.

## Axis 2: permission breadth (what the GitHub role can do)

Only permissions attached to the GitHub-trusted role(s) count. Other roles in
the same file (ECS task roles, EKS node roles, Lambda execution roles) are
ignored. When no role can be identified (bare policy JSON, CDK/Pulumi code), the
file-level grade is used.

| Code | Meaning |
|---|---|
| P0 | Read-only |
| P1 | Writes only on named resources, in any number of services |
| P2 | `service:*` actions; writes on `*` or on every resource of a type (`function:*`); `NotAction`; `*FullAccess`; `ReadOnlyAccess`; a service-scoped PowerUser/Administrator managed policy; EKS `AmazonEKSClusterAdminPolicy` |
| P3 | `*`, `*:*`, `AdministratorAccess`, `PowerUserAccess`, `IAMFullAccess`, any `iam:` write including `PassRole`, or `sts:AssumeRole` on any role or the CDK bootstrap roles |
| PU2 | Nothing attached to the GitHub role is visible |
| N/A | U3 items |

Rules:

5. **Scope, not service count.** One named bucket plus one named CloudFront
   distribution is P1. Actions that AWS only accepts on `Resource: "*"`
   (`ecr:GetAuthorizationToken`, `sts:GetCallerIdentity`, ...) do not count as
   writes on `*`. S3 ARNs carry no type prefix, so `arn:aws:s3:::bucket/*` is a
   named bucket.
6. **Other files only by explicit link.** Permissions in another file of the
   repository count only when that file attaches a policy to this role by
   resource reference or role name, or when the role there loads this trust
   file (`file("...trust.json")`). Otherwise PU2. The resolver never takes a
   repository-wide union.

7. **Role chaining.** `sts:AssumeRole` in a permission policy lets the role
   become other roles. On `*`, `role/*`, or the CDK bootstrap roles (`role/cdk-*`)
   it is P3: the default CDK bootstrap gives the CloudFormation execution role
   AdministratorAccess. On other named roles it counts as a write (P1).

Statements that carry a `Principal` (bucket, key and queue policies, trust
policies) are resource-based policies, not the role's permissions, and are not
graded. EKS access policies (Kubernetes-level, attached via access entries):
ClusterAdmin P2, Admin/Edit P1, View P0.

## Changes from v1 (after the pass-1 development round)

| Area | v1 | v2 | Why |
|---|---|---|---|
| Non-literal sub values | read as "no sub" (S0) by the tool | resolved from the file, else U1 | the tool's S0 precision was 0.00 in pass 1 |
| Wildcard ref/environment | counted as pinned (S3/S4) | S2 | rule 2 |
| Owner prefix wildcard, `@*` | unspecified | S0; `@*` ignored | rule 3 |
| Scope | "not a GitHub Actions trust policy" | AWS IAM only, examples listed | rater and tool disagreed on Azure/GCP/test files |
| P1 vs P2 | multi-service = P2 | resource scope decides | rule 5; rater's pass-1 judgments |
| Breadth scope | whole file | GitHub role only | other roles inflated breadth |
| Other files | "visible in what's shown" | explicit link only | rule 6 |
| Role chaining | `sts:AssumeRole` ignored as a trust action | graded (rule 7) | CDK deploy roles reach admin through bootstrap roles |
| Resource policies | graded with the role | not graded | bucket policies were mistaken for role permissions |

Pass-1 results (kappa 0.47 trust, 0.33 breadth) are reported as the
development round. They are not adjudicated and are not the validation result.
The validation result is the held-out sample labeled with v2.
