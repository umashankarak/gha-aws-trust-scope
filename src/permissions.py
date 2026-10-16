"""
Axis 2 -- permission breadth ("blast radius") behind the GitHub-trusted role.

Grades how much the role can DO once assumed, to pair with the Axis 1 grade for
how tightly it can be assumed. The paper's core cross-tab is loose trust (S0-S2)
x broad permission (P2-P3).

Breadth ladder (codebook v2, after the pass-1 review):
  P0  read-only
  P1  writes limited to NAMED resources -- in any number of services
  P2  a service-wide action wildcard (s3:*), writes on every resource ('*' or an
      ARN whose resource part is '*'), NotAction, *FullAccess, ReadOnlyAccess,
      or a service-scoped PowerUser/Administrator managed policy
  P3  admin-equivalent: '*' action, '*:*', AdministratorAccess/PowerUserAccess/
      IAMFullAccess, or any iam: write (privilege escalation / PassRole)

  Rule 5 (v2): breadth is decided by RESOURCE SCOPE, not by how many services a
  role touches. A deploy role that writes one named bucket and invalidates one
  named distribution is P1, not P2. Actions AWS only accepts on Resource '*'
  (ecr:GetAuthorizationToken, sts:GetCallerIdentity, ...) do not count as
  writes on '*'.

  Role scoping (v2): only permissions attached to the GitHub-trusted role(s) in
  the file count. Other roles in the same file (ECS task roles, EKS node roles,
  Lambda execution roles) are ignored. When no role can be identified (bare
  policy JSON, CDK/Pulumi code), the file-level grade is used.

Dispositions:
  PU2  no permission attached to the GitHub role is visible in the file
"""

from __future__ import annotations

import json
import re

from classify import (EXPR, GH_ISSUER, _HclParser, _brace_body, _definitions,
                      _flatten, _hcl_list)

# Action verbs that are reads. Anything else counts as a write/sensitive action.
_READ_PREFIXES = (
    "get", "list", "describe", "head", "search", "view", "lookup",
    "batchget", "scan", "query", "read", "generatecredentialreport",
    "generateservicelastaccessed", "simulate", "estimate", "filter", "select",
)

# Write-classed actions that AWS only accepts on Resource "*". Granting them on
# "*" is the only way to grant them, so it is not evidence of a broad role.
_STAR_ONLY = {
    "ecr:getauthorizationtoken", "ecr-public:getauthorizationtoken",
    "sts:getcalleridentity", "sts:getservicebearertoken",
    "cloudformation:validatetemplate", "cloudwatch:putmetricdata",
    "xray:puttracesegments", "xray:puttelemetryrecords",
    "codeartifact:getauthorizationtoken",
}

# AWS-managed policy names -> breadth. Suffix/keyword rules cover the rest.
_MANAGED = {
    "administratoraccess": "P3",
    "poweruseraccess": "P3",       # everything except IAM -- still account-wide
    "iamfullaccess": "P3",
    "readonlyaccess": "P2",        # read across ALL services (data exfiltration)
    "databaseadministrator": "P3",
    "systemadministrator": "P3",
}

# EKS access policies (Kubernetes-level, attached via access entries).
_EKS_ACCESS = {
    "amazoneksclusteradminpolicy": "P2",
    "amazoneksadminpolicy": "P1",
    "amazonekseditpolicy": "P1",
    "amazoneksviewpolicy": "P0",
}

_MANAGED_ARN = re.compile(r'arn:[^:\s"\']*:iam::aws:policy/([A-Za-z0-9+=,.@_/-]+)')
_CUSTOM_ARN = re.compile(r'arn:aws:iam::\d{12}:policy/([A-Za-z0-9+=,.@_/-]+)')
_EKS_ARN = re.compile(r'arn:aws:eks::aws:cluster-access-policy/([A-Za-z0-9]+)')
_CDK_MANAGED = re.compile(r'fromAwsManagedPolicyName\(\s*[\'"`]([^\'"`]+)')

# Regex fallback for text no parser can read (pairs all actions with all resources).
_ACTIONS = re.compile(r'"?[Aa]ctions?"?\s*[:=]\s*(\[.*?\]|"[^"]*")', re.DOTALL)
_RESOURCES = re.compile(r'"?[Rr]esources?"?\s*[:=]\s*(\[.*?\]|"[^"]*")', re.DOTALL)
_QUOTED = re.compile(r'"([^"]*)"')

# Actions that only make sense in a trust policy. sts:AssumeRole is NOT here:
# in a permission policy it lets the role chain into other roles (rule 7).
_TRUST_ACTIONS = ("assumerolewithwebidentity", "assumerolewithsaml",
                  "tagsession", "assumerolewithoidc", "setsourceidentity")
# CDK bootstrap roles. The default bootstrap gives the CloudFormation execution
# role AdministratorAccess, so a role that can assume them can deploy anything.
_CDK_BOOTSTRAP_ROLE = re.compile(r':role/cdk-', re.IGNORECASE)

_ORDER = ["P0", "P1", "P2", "P3"]


def _broadest(grades):
    present = [g for g in grades if g in _ORDER]
    return max(present, key=_ORDER.index) if present else None


def _is_write(action: str) -> bool:
    if action == "*" or action.endswith(":*"):
        return True
    verb = action.split(":", 1)[1] if ":" in action else action
    verb = verb.lstrip("*").lower()
    return not any(verb.startswith(r) for r in _READ_PREFIXES)


_RESOURCE_TYPES = {
    "function", "layer", "table", "parameter", "repository", "log-group", "distribution",
    "secret", "stack", "instance", "key", "alias", "role", "policy", "user", "group",
    "cluster", "service", "task-definition", "task", "statemachine", "execution",
    "volume", "snapshot", "image", "rule", "event-bus", "certificate", "domain",
    "restapis", "apis", "hostedzone", "change", "project", "pipeline", "application",
    "deploymentgroup", "loadbalancer", "targetgroup", "security-group", "vpc", "subnet",
}


def _broad_resource(r: str) -> bool:
    """'*', or an ARN whose resource part is only a wildcard (all functions,
    all buckets, ...). 'arn:aws:s3:::my-bucket/*' is a NAMED resource."""
    r = re.sub(r'\$\{[^}]*\}', 'X', r.strip())  # ${AWS::Region} etc. contain ':'
    if r == "*":
        return True
    if r.startswith("arn:"):
        parts = r.split(":", 5)
        if len(parts) < 6:
            return False
        service, portion = parts[2], parts[5]
        if portion in ("*", ""):
            return True
        m = re.fullmatch(r'([A-Za-z-]+)[:/]\*', portion)
        # 'function:*', 'table/*' = every resource of a type. S3 ARNs have no type
        # prefix, so 'arn:aws:s3:::name/*' is objects in ONE named bucket.
        return bool(m) and service != "s3" and m.group(1).lower() in _RESOURCE_TYPES
    return False


def grade_managed(name: str) -> str | None:
    n = name.strip().lower().split("/")[-1]
    if n in _MANAGED:
        return _MANAGED[n]
    if n.endswith("fullaccess") or n.endswith("_fullaccess"):
        return "P2"
    if "readonly" in n or "viewonly" in n or n.endswith("pullonly"):
        return "P0"
    # A service-scoped PowerUser/Administrator (e.g. AmazonEC2ContainerRegistry
    # PowerUser) is broad within ONE service -> P2, NOT account-wide P3.
    if "poweruser" in n or "administrator" in n or n.endswith("admin"):
        return "P2"
    return None  # unknown managed policy -- contents not knowable from the name


def grade_actions(actions, resources, not_action: bool = False) -> str | None:
    """Grade ONE statement (its actions and the resources they apply to)."""
    acts = [a for a in actions if isinstance(a, str) and a]
    acts = [a for a in acts if a.split(":", 1)[-1].lower() not in _TRUST_ACTIONS]
    res = [r for r in resources if isinstance(r, str)]
    wild = any(_broad_resource(r) for r in res)
    # Rule 7: role chaining. Assuming any role ('*', 'role/*') or the CDK
    # bootstrap roles is admin-equivalent; assuming named roles is a write.
    if any(a.lower() == "sts:assumerole" for a in acts):
        if wild or any(_CDK_BOOTSTRAP_ROLE.search(r) or r.endswith(":role/*") for r in res):
            return "P3"
    if not_action:
        return "P3" if wild else "P2"
    if not acts:
        return None

    if "*" in acts:
        return "P3"
    for a in acts:
        low = a.lower()
        if low in ("iam:*", "sts:*", "*:*"):
            return "P3"
        if low.startswith("iam:") and _is_write(a):
            return "P3"  # iam writes (PassRole, CreatePolicy, ...) = escalation

    if any(a.endswith(":*") for a in acts):
        return "P2"
    writes = [a for a in acts if _is_write(a)]
    broad_writes = [a for a in writes if a.lower() not in _STAR_ONLY]
    if broad_writes and wild:
        return "P2"
    if writes:
        return "P1"
    return "P0"


# ---------------------------------------------------------------------------
# Statement extraction
# ---------------------------------------------------------------------------

def _as_list(v):
    return v if isinstance(v, list) else [v]


def _statements_from_obj(obj) -> list[tuple[list, list, bool]]:
    """(actions, resources, not_action) for every Allow statement in a parsed
    JSON/YAML/HCL-object structure."""
    out = []

    def walk(o):
        if isinstance(o, dict):
            keys = set(o)
            if ("Action" in keys or "NotAction" in keys) and ("Effect" in keys or "Resource" in keys):
                # A statement with a Principal is a resource-based policy (bucket,
                # key, queue policy) or a trust policy: not the role's identity
                # permissions.
                if str(o.get("Effect", "Allow")).lower() != "deny" and "Principal" not in keys:
                    acts = _flatten(o.get("Action", []))
                    res = _flatten(o.get("Resource", o.get("NotResource", [])))
                    out.append((acts, res, "NotAction" in keys))
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(obj)
    return out


def _native_doc_statements(block: str) -> list[tuple[list, list, bool]]:
    """Statements of one `data "aws_iam_policy_document"` body."""
    out = []
    for sm in re.finditer(r'\bstatement\s*\{', block):
        sbody = _brace_body(block, sm.end() - 1)
        if re.search(r'\beffect\s*=\s*"Deny"', sbody) or re.search(r'\bprincipals\s*\{', sbody):
            continue  # Deny, or a resource-based / trust statement (has principals)
        acts = _hcl_list(sbody, "actions")
        not_acts = _hcl_list(sbody, "not_actions")
        res = _hcl_list(sbody, "resources")
        if acts or not_acts:
            out.append((acts or not_acts, res, bool(not_acts and not acts)))
    return out


def _data_docs(text: str) -> dict[str, str]:
    return {m.group(1): _brace_body(text, text.index("{", m.start()))
            for m in re.finditer(r'data\s+"aws_iam_policy_document"\s+"([A-Za-z0-9_-]+)"\s*\{', text)}


_PATH_TOK = re.compile(r'\.([A-Za-z_][\w-]*)|\[\s*"([^"]+)"\s*\]|\[\s*(\d+)\s*\]')
_LOCAL_REF = re.compile(r'(?:\$\{)?((?:local|var)\.[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*|\[[^\]]*\])*)\}?')


def _deref(v, text: str, depth: int = 0):
    """Replace local./var. references inside a parsed HCL value with what they
    are defined as in the same file (locals, variable defaults), following
    attribute and index paths: local.roles["ci"].policy_statements."""
    if depth > 5:
        return v
    if isinstance(v, str) and v.startswith(EXPR) and "(" in v:
        # concat([...], [...]), flatten([...]), merge(...): parse the arguments
        # as a list so the statements inside stay visible.
        inner = v[v.index("(") + 1:v.rindex(")")] if ")" in v else ""
        try:
            args = _HclParser("[" + inner + "]").parse()
        except Exception:  # noqa: BLE001
            return v
        flat = []
        for a in args or []:
            flat += a if isinstance(a, list) else [a]
        return _deref(flat, text, depth + 1)
    if isinstance(v, str):
        m = _LOCAL_REF.fullmatch(v.strip())
        if not m:
            return v
        ref = m.group(1)
        head = re.match(r'(?:local|var)\.([A-Za-z_][\w-]*)', ref)
        rest = ref[head.end():]
        for rhs in _definitions(head.group(1), {"text": text}):
            try:
                obj = _HclParser(rhs).parse()
            except Exception:  # noqa: BLE001
                continue
            for t in _PATH_TOK.finditer(rest):
                key, idx = t.group(1) or t.group(2), t.group(3)
                if isinstance(obj, dict) and key in obj:
                    obj = obj[key]
                elif isinstance(obj, list) and idx is not None and int(idx) < len(obj):
                    obj = obj[int(idx)]
                else:
                    obj = None
                    break
            if obj is not None and obj != v:
                return _deref(obj, text, depth + 1)
        return v
    if isinstance(v, dict):
        return {k: _deref(x, text, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [_deref(x, text, depth + 1) for x in v]
    return v


def _jsonencode_bodies(expr: str) -> list[str]:
    out = []
    for m in re.finditer(r"jsonencode\s*\(", expr):
        start = expr.index("(", m.start())
        depth, i = 0, start
        while i < len(expr):
            if expr[i] in "({[":
                depth += 1
            elif expr[i] in ")}]":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append(expr[start + 1:i])
    return out


def _hcl_policy_statements(expr: str, text: str, docs: dict) -> list:
    """Statements for a policy expression found in HCL: jsonencode(...) (with
    local./var. references resolved from the file), a
    data.aws_iam_policy_document.X[0].json reference, or a heredoc of raw JSON."""
    stmts = []
    for body in _jsonencode_bodies(expr):
        try:
            parsed = _HclParser(body).parse()
        except Exception:  # noqa: BLE001
            continue
        stmts += _statements_from_obj(_deref(parsed, text))
    for name in re.findall(r'data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?\.json', expr):
        if name in docs:
            stmts += _native_doc_statements(docs[name])
    for hm in re.finditer(r'<<-?\s*(\w+)\n(.*?)\n\s*\1', expr, re.DOTALL):
        try:
            stmts += _statements_from_obj(json.loads(hm.group(2)))
        except (ValueError, TypeError):
            pass
    return stmts


# ---------------------------------------------------------------------------
# Terraform role scoping
# ---------------------------------------------------------------------------

_ROLE_BLOCK = re.compile(r'resource\s+"aws_iam_role"\s+"([A-Za-z0-9_-]+)"\s*\{')
_ATTACH_BLOCK = re.compile(r'resource\s+"aws_iam_role_policy_attachment"\s+"[A-Za-z0-9_-]+"\s*\{')
_POLICY_ATTACH_BLOCK = re.compile(r'resource\s+"aws_iam_policy_attachment"\s+"[A-Za-z0-9_-]+"\s*\{')
_INLINE_BLOCK = re.compile(r'resource\s+"aws_iam_role_policy"\s+"[A-Za-z0-9_-]+"\s*\{')
_POLICY_BLOCK = re.compile(r'resource\s+"aws_iam_policy"\s+"([A-Za-z0-9_-]+)"\s*\{')
_DATA_POLICY_BLOCK = re.compile(r'data\s+"aws_iam_policy"\s+"([A-Za-z0-9_-]+)"\s*\{')
_EKS_ASSOC_BLOCK = re.compile(r'resource\s+"aws_eks_access_policy_association"\s+"[A-Za-z0-9_-]+"\s*\{')
_NAME_ATTR = re.compile(r'\bname\s*=\s*"([^"]+)"')
_ROLE_REF = re.compile(r'\brole\s*=\s*([^\n]+)')
_ROLES_REF = re.compile(r'\broles\s*=\s*(\[[^\]]*\])', re.DOTALL)
_POLICY_ARN_REF = re.compile(r'\bpolicy_arn\s*=\s*([^\n]+)')
_PRINCIPAL_ARN_REF = re.compile(r'\bprincipal_arn\s*=\s*([^\n]+)')


def _blocks(text, header_re):
    """Yield (match, body_text) for each `resource "..." "..." {` block."""
    for m in header_re.finditer(text):
        brace = text.index("{", m.start())
        yield m, _brace_body(text, brace)


def github_roles(file_text: str) -> list[tuple[str, str | None]]:
    """
    GitHub-trust role resource names in a file, with their literal `name` if any.
    A role is GitHub if its assume_role_policy resolves to a github trust: inline
    issuer, or a reference to a data.aws_iam_policy_document whose block in this
    file carries the issuer.
    """
    gh_docs = {n for n, body in _data_docs(file_text).items() if GH_ISSUER in body}
    roles = []
    for m, body in _blocks(file_text, _ROLE_BLOCK):
        name_attr = _NAME_ATTR.search(body)
        arp = re.search(r'assume_role_policy\s*=\s*([^\n]+)', body)
        is_gh = GH_ISSUER in body
        if arp:
            ref = arp.group(1)
            is_gh = is_gh or any(f"aws_iam_policy_document.{d}" in ref for d in gh_docs)
        if is_gh:
            roles.append((m.group(1), name_attr.group(1) if name_attr else None))
    # Fallback: a github-coded file with exactly one role and no explicit link.
    if not roles and GH_ISSUER in file_text:
        allroles = list(_blocks(file_text, _ROLE_BLOCK))
        if len(allroles) == 1:
            m, body = allroles[0]
            na = _NAME_ATTR.search(body)
            roles.append((m.group(1), na.group(1) if na else None))
    return roles


def _ref_matches_role(ref: str, resource_name: str, name_attr: str | None) -> bool:
    if re.search(rf'aws_iam_role\.{re.escape(resource_name)}\b', ref):
        return True
    if name_attr and f'"{name_attr}"' in ref:
        return True
    return False


def _grade_managed_text(s: str, tag: str, grades: list, evidence: list):
    for name in _MANAGED_ARN.findall(s):
        g = grade_managed(name)
        evidence.append(f"{tag}managed:{name.split('/')[-1]}={g or '?'}")
        if g:
            grades.append(g)
    for name in _EKS_ARN.findall(s):
        g = _EKS_ACCESS.get(name.lower())
        if g:
            grades.append(g); evidence.append(f"{tag}eks:{name}={g}")


def _grade_stmts(stmts, tag: str, grades: list, evidence: list):
    gs = [grade_actions(a, r, na) for a, r, na in stmts]
    g = _broadest(gs)
    if g:
        grades.append(g); evidence.append(f"{tag}={g}")


def resolve_role_breadth(text: str, resource_name: str, name_attr: str | None):
    """
    Grade the broadest permission attached to ONE Terraform role, searching the
    given text (one file, or the concatenated repo IaC text). Links strictly by
    reference to this role -- never a file- or repo-wide union.
    Returns (breadth or None, evidence list).
    """
    grades, evidence = [], []
    docs = _data_docs(text)
    policy_blocks = {m.group(1): body for m, body in _blocks(text, _POLICY_BLOCK)}
    data_policies = {m.group(1): body for m, body in _blocks(text, _DATA_POLICY_BLOCK)}

    def from_policy_arn(arn: str, tag: str):
        _grade_managed_text(arn, tag, grades, evidence)
        for pname in re.findall(r'(?<!data\.)aws_iam_policy\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?\.arn', arn):
            if pname in policy_blocks:
                _grade_stmts(_hcl_policy_statements(policy_blocks[pname], text, docs),
                             f"{tag}custom:{pname}", grades, evidence)
        for dname in re.findall(r'data\.aws_iam_policy\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?\.arn', arn):
            if dname in data_policies:
                _grade_managed_text(data_policies[dname], tag, grades, evidence)

    # The role block itself: managed_policy_arns, inline_policy blocks.
    for m, body in _blocks(text, _ROLE_BLOCK):
        if m.group(1) != resource_name:
            continue
        mp = re.search(r'managed_policy_arns\s*=\s*', body)
        if mp:
            from_policy_arn(body[mp.end():mp.end() + 2000].split("]")[0], "role.")
        for im in re.finditer(r'\binline_policy\s*\{', body):
            _grade_stmts(_hcl_policy_statements(_brace_body(body, im.end() - 1), text, docs),
                         "role.inline", grades, evidence)

    for _m, body in _blocks(text, _ATTACH_BLOCK):
        ref = _ROLE_REF.search(body)
        parn = _POLICY_ARN_REF.search(body)
        if ref and parn and _ref_matches_role(ref.group(1), resource_name, name_attr):
            from_policy_arn(parn.group(1), "attach.")

    for _m, body in _blocks(text, _POLICY_ATTACH_BLOCK):
        ref = _ROLES_REF.search(body)
        parn = _POLICY_ARN_REF.search(body)
        if ref and parn and _ref_matches_role(ref.group(1), resource_name, name_attr):
            from_policy_arn(parn.group(1), "attach.")

    for _m, body in _blocks(text, _INLINE_BLOCK):
        ref = _ROLE_REF.search(body)
        if ref and _ref_matches_role(ref.group(1), resource_name, name_attr):
            _grade_stmts(_hcl_policy_statements(body, text, docs), "inline-policy", grades, evidence)

    for _m, body in _blocks(text, _EKS_ASSOC_BLOCK):
        ref = _PRINCIPAL_ARN_REF.search(body)
        parn = _POLICY_ARN_REF.search(body)
        if ref and parn and _ref_matches_role(ref.group(1), resource_name, name_attr):
            _grade_managed_text(parn.group(1), "eks-access.", grades, evidence)

    return _broadest(grades), evidence


# ---------------------------------------------------------------------------
# CloudFormation role scoping
# ---------------------------------------------------------------------------

def _load_cfn(text: str):
    t = text.lstrip()
    if t.startswith("{"):
        try:
            return json.loads(text)
        except ValueError:
            return None
    try:
        import yaml
    except ImportError:
        return None

    class _CfnLoader(yaml.SafeLoader):
        pass

    def _passthrough(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    _CfnLoader.add_multi_constructor("!", _passthrough)
    try:
        return yaml.load(text, Loader=_CfnLoader)
    except yaml.YAMLError:
        return None


def _cfn_role_scoped(doc) -> tuple[list, list] | None:
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    if not isinstance(resources, dict):
        return None
    gh = []
    for lid, r in resources.items():
        if not isinstance(r, dict) or r.get("Type") != "AWS::IAM::Role":
            continue
        props = r.get("Properties") or {}
        trust = json.dumps(props.get("AssumeRolePolicyDocument", {}), default=str)
        if GH_ISSUER in trust or "AssumeRoleWithWebIdentity" in trust:
            gh.append(lid)
    if not gh:
        return None

    grades, evidence = [], []

    def refs_role(v) -> bool:
        return any(any(lid == s or f"${{{lid}}}" in s for lid in gh) for s in _flatten(v))

    for lid in gh:
        props = resources[lid].get("Properties") or {}
        for arn in _flatten(props.get("ManagedPolicyArns", [])):
            _grade_managed_text(arn, "role.", grades, evidence)
            m = re.fullmatch(r'\$\{([A-Za-z0-9]+)\}', arn)  # Ref to a ManagedPolicy here
            if m and isinstance(resources.get(m.group(1)), dict):
                pdoc = (resources[m.group(1)].get("Properties") or {}).get("PolicyDocument", {})
                _grade_stmts(_statements_from_obj(pdoc), f"role.custom:{m.group(1)}", grades, evidence)
        for pol in _as_list(props.get("Policies", [])):
            if isinstance(pol, dict):
                _grade_stmts(_statements_from_obj(pol.get("PolicyDocument", {})),
                             "role.inline", grades, evidence)
    for lid, r in resources.items():
        if not isinstance(r, dict) or r.get("Type") not in (
                "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::RolePolicy"):
            continue
        props = r.get("Properties") or {}
        if refs_role(props.get("Roles", [])) or refs_role(props.get("RoleName", "")):
            _grade_stmts(_statements_from_obj(props.get("PolicyDocument", {})),
                         f"policy:{lid}", grades, evidence)
    return grades, evidence


# ---------------------------------------------------------------------------
# CDK / Pulumi (file-level; roles cannot be separated reliably)
# ---------------------------------------------------------------------------

_CDK_STMT = re.compile(r'PolicyStatement\s*\(\s*\{')
_GRANT = re.compile(r'\.grant(\w*)\s*\(')


def _ts_strings(s: str) -> list[str]:
    return re.findall(r'[\'"`]([^\'"`]*)[\'"`]', s)


def _cdk_statements(text: str) -> list:
    out = []
    for m in _CDK_STMT.finditer(text):
        body = _brace_body(text, m.end() - 1)
        if re.search(r'effect\s*:\s*\w*\.?Effect\.DENY', body):
            continue
        am = re.search(r'\bactions\s*:\s*\[(.*?)\]', body, re.DOTALL)
        nm = re.search(r'\bnotActions\s*:\s*\[(.*?)\]', body, re.DOTALL)
        rm = re.search(r'\bresources\s*:\s*\[(.*?)\]', body, re.DOTALL)
        acts = _ts_strings(am.group(1)) if am else []
        res = _ts_strings(rm.group(1)) if rm else []
        if rm and not res:
            res = ["<ref>"]
        if acts or nm:
            out.append((acts or _ts_strings(nm.group(1)), res, bool(nm and not am)))
    return out


def _grant_grade(kind: str) -> str:
    k = kind.lower()
    if k in ("", "principal"):
        return "P1"
    if "passrole" in k:
        return "P3"
    if k.startswith("read") and "write" not in k or k in ("pull", "describe", "list"):
        return "P0"
    return "P1"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _file_level(text: str, kind: str, doc) -> tuple[list, list]:
    """Every Allow statement / managed attachment in the file (no role scoping)."""
    grades, evidence = [], []
    _grade_managed_text(text, "", grades, evidence)
    stmts = []
    if doc is not None:
        stmts = _statements_from_obj(doc)
    elif kind == "hcl":
        for body in _jsonencode_bodies(text):
            try:
                stmts += _statements_from_obj(_deref(_HclParser(body).parse(), text))
            except Exception:  # noqa: BLE001
                pass
        for body in _data_docs(text).values():
            if GH_ISSUER not in body:
                stmts += _native_doc_statements(body)
    elif kind == "ts":
        stmts = _cdk_statements(text)
        for name in _CDK_MANAGED.findall(text):
            g = grade_managed(name)
            if g:
                grades.append(g); evidence.append(f"managed:{name}={g}")
        for kind_ in _GRANT.findall(text):
            g = _grant_grade(kind_)
            grades.append(g); evidence.append(f"grant{kind_}={g}")
    if not stmts and doc is None:
        acts = [a for m in _ACTIONS.finditer(text) for a in _QUOTED.findall(m.group(1))]
        res = [r for m in _RESOURCES.finditer(text) for r in _QUOTED.findall(m.group(1))]
        if acts:
            stmts = [(acts, res, False)]
    _grade_stmts(stmts, "inline", grades, evidence)
    return grades, evidence


def _kind(text: str, suffix: str | None) -> str:
    s = (suffix or "").lower()
    if s == ".tf":
        return "hcl"
    if s in (".ts", ".js", ".mjs", ".py"):
        return "ts"
    if s in (".json", ".yaml", ".yml", ".template"):
        return "cfn"
    t = text.lstrip()
    if t.startswith("{") or "Resources:" in text or "AWSTemplateFormatVersion" in text:
        return "cfn"
    if re.search(r'\b(resource|data)\s+"aws_', text):
        return "hcl"
    return "ts"


def classify_permissions(text: str, suffix: str | None = None) -> tuple[str, str]:
    """
    Return (breadth, evidence) for the GitHub-trusted role(s) in the file.
    breadth is P0-P3, or PU2 when no permission attached to that role is visible.
    """
    kind = _kind(text, suffix)
    grades, evidence, scope = None, None, "file"

    if kind == "cfn":
        doc = _load_cfn(text)
        scoped = _cfn_role_scoped(doc) if doc is not None else None
        if scoped is not None:
            grades, evidence = scoped
            scope = "role"
        else:
            grades, evidence = _file_level(text, kind, doc)
    elif kind == "hcl":
        roles = github_roles(text)
        if roles:
            grades, evidence = [], []
            for rn, na in roles:
                b, ev = resolve_role_breadth(text, rn, na)
                if b:
                    grades.append(b)
                evidence += ev
            scope = "role"
        else:
            grades, evidence = _file_level(text, kind, None)
    else:
        grades, evidence = _file_level(text, kind, None)

    breadth = _broadest(grades)
    if breadth is None:
        custom = _CUSTOM_ARN.findall(text)
        if custom:
            return "PU2", f"custom-policy-arn-only:{custom[0].split('/')[-1]}"
        return "PU2", ("no permission attached to the GitHub role in file" if scope == "role"
                       else "no permission policy in file")
    return breadth, f"[{scope}] " + "; ".join(evidence[:6])
