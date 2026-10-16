"""
Axis 1 classifier for CI-to-cloud OIDC trust policies.

Codes a trust policy by SCOPE ADMITTED -- the population of GitHub Actions
OIDC tokens the policy will accept -- not by whether the author erred.

Rungs (see codebook):
  S0  no usable sub constraint, or a wildcard in the owner position
  S1  organization wildcard: any repo in one org, including repos not yet created
  S2  repo pinned, ref unconstrained: any branch or tag of that repo
  S3  repo + a specific context (ref, pull_request) pinned
  S4  environment-pinned, or constrained on job_workflow_ref

Dispositions:
  U1  rung turns on a value we cannot resolve
  U3  matched the frame but is not a GitHub Actions CI federation

Deliberately NOT handled here (manual adjudication, logged):
  - repo_property_* ABAC conditions (Mar 2026 custom properties): admitted set
    is dynamic and defined outside the repo. Returns U1 with reason.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

GH_ISSUER = "token.actions.githubusercontent.com"

# A Terraform interpolation that survived jsonencode, e.g. ${var.repo_name}
INTERP = re.compile(r"\$\{[^}]*\}")
# A bare HCL reference the HCL parser hands back for `= var.foo`
BARE_REF = re.compile(r"^\$\{?(var|local|each|data)\.[\w.\[\]\"-]+\}?$")

RUNG_ORDER = ["S0", "S1", "S2", "S3", "S4"]


@dataclass
class Coding:
    rung: str
    aud_constrained: bool
    sub_format: str  # historical | immutable | mixed | none
    reason: str = ""
    sub_patterns: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def _loosest(rungs: list[str]) -> str:
    """Admitted population is the union, so the loosest element governs."""
    return min(rungs, key=RUNG_ORDER.index)


def _placeholder(value: str) -> str:
    """Replace interpolations with a sentinel so structure stays codeable."""
    return INTERP.sub("\x00", value)


def _fmt(body: str) -> str:
    """
    Immutable subjects (post 2026-07-15) carry @<numeric id> on owner and repo.
    Any repo: subject without an @id is the historical name-based format --
    interpolated owner/repo (${var}) is still historical, since the immutable
    format always writes the literal @id.
    """
    return "immutable" if "@" in body else "historical"


# ---------------------------------------------------------------------------
# Sub-value resolution (codebook rule 1)
#
# A sub condition whose value is not a literal string -- local.x, var.x,
# format(...), concat(...), a ternary, {"Fn::Sub": ...}, !Sub, !If, a CDK
# template literal -- is still a sub condition. It must never be read as "no
# sub" (that was the pass-1 S0 bug). We resolve it from the SAME file when we
# can: locals, variable/parameter defaults, for-comprehension templates,
# format() templates. Placeholders inside the resolved template count as named
# values. Only when nothing in the file gives the shape does it become U1.
# ---------------------------------------------------------------------------

EXPR = "\x01"  # prefix marking a raw, not-yet-resolved expression
_REF_NAME = re.compile(r'\b(?:local|var|each\.value|each|self)\.([A-Za-z_][\w-]*)')
_CFN_NAME = re.compile(r'\$\{([A-Za-z_][\w]*)\}')


def _quoted_strings(s: str) -> list[str]:
    """Double-quoted strings in s, keeping ${...} interpolations (and any quotes
    inside them) intact, e.g. "repo:${replace(var.e, ":", "%3A")}" is one string."""
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i] != '"':
            i += 1
            continue
        i += 1
        buf, depth = [], 0
        while i < n:
            c = s[i]
            if c == "\\" and i + 1 < n:
                buf.append(s[i:i + 2]); i += 2; continue
            if s.startswith("${", i):
                depth += 1; buf.append("${"); i += 2; continue
            if c == "}" and depth:
                depth -= 1
            elif c == '"' and depth == 0:
                break
            buf.append(c); i += 1
        out.append("".join(buf))
        i += 1
    return out


def _rhs_extent(text: str, i: int, cap: int = 6000) -> str:
    """The right-hand side starting at i: up to end of line, extended while any
    (, [ or { is still open. String-aware so brackets inside quotes don't count."""
    n, start, depth, in_str = len(text), i, 0, False
    while i < n and i - start < cap:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2; continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                break
        elif c == "\n" and depth <= 0:
            break
        i += 1
    return text[start:i]


def _definitions(name: str, ctx: dict) -> list[str]:
    """Right-hand sides that define `name` in the same file."""
    out = []
    params = ctx.get("params") or {}
    if name in params:
        v = params[name]
        vals = v if isinstance(v, list) else [v]
        out.append(" ".join('"%s"' % x for x in vals if isinstance(x, str)))
    text = ctx.get("text") or ""
    if not text:
        return out
    esc = re.escape(name)
    # HCL locals / object attributes / tfvars:  name = <rhs>
    for m in re.finditer(rf'(?m)^[ \t]*"?{esc}"?[ \t]*=[ \t]*', text):
        out.append(_rhs_extent(text, m.end()))
    # Terraform variable default
    for m in re.finditer(rf'variable\s+"{esc}"\s*\{{', text):
        body = _brace_body(text, m.end() - 1)
        d = re.search(r'\bdefault\s*=\s*', body)
        if d:
            out.append(_rhs_extent(body, d.end()))
    # TS/JS const (CDK, Pulumi)
    for m in re.finditer(rf'\b(?:const|let|var)\s+{esc}\s*(?::[^=\n]+)?=\s*', text):
        out.append(_rhs_extent(text, m.end()))
    return out[:6]


def _is_subject_template(s: str) -> bool:
    return s.startswith("repo:") or bool(re.match(r'\$\{[^}]+\}:', s))


def _expand(value: str, ctx: dict, depth: int = 0) -> list[str]:
    """Resolve one sub value to concrete subject templates. [] = unresolvable."""
    if depth > 4:
        return []
    if value.startswith("repo:"):
        return [value]
    m = re.match(r'\$\{([^}]*)\}', value)
    if m and m.end() < len(value):
        # Prefix form "${local.subject_prefix}:environment:prod"
        heads = [h for h in _expand(EXPR + m.group(1), ctx, depth + 1) if h.startswith("repo:")]
        return [h + value[m.end():] for h in heads][:12]
    expr = value[1:] if value.startswith(EXPR) else value
    if m and m.end() == len(value):
        expr = m.group(1)  # whole-value reference ${local.x} / ${Param}
    strings = _quoted_strings(expr)
    if "format(" in expr:
        strings = [re.sub(r'%[svdq]', '${fmt}', x) for x in strings]
    found = []
    for x in strings:
        if _is_subject_template(x):
            found += _expand(x, ctx, depth + 1)
    if found:
        return list(dict.fromkeys(found))[:12]
    names = _REF_NAME.findall(expr) + _CFN_NAME.findall(expr)
    if not names and re.fullmatch(r'[A-Za-z_][\w]*', expr.strip()):
        names = [expr.strip()]  # bare CloudFormation parameter name from !Ref
    for name in dict.fromkeys(names):
        for rhs in _definitions(name, ctx):
            found += _expand(EXPR + rhs, ctx, depth + 1)
    return list(dict.fromkeys(found))[:12]


def _flatten(val) -> list[str]:
    """Condition values -> strings. CloudFormation intrinsics are unwrapped to
    their template (Fn::Sub) or a ${Param} reference (Ref)."""
    if isinstance(val, str):
        return [val]
    if isinstance(val, dict):
        if "Fn::Sub" in val:
            v = val["Fn::Sub"]
            return _flatten(v[0] if isinstance(v, list) and v else v)
        if "Ref" in val and isinstance(val["Ref"], str):
            return ["${%s}" % val["Ref"]]
        if "Fn::Join" in val and isinstance(val["Fn::Join"], list) and len(val["Fn::Join"]) == 2:
            sep, parts = val["Fn::Join"]
            if isinstance(parts, list):
                return [str(sep).join(_flatten(p)[0] if _flatten(p) else "${x}" for p in parts)]
        out = []
        for v in val.values():
            out += _flatten(v)
        return out
    if isinstance(val, list):
        out = []
        for v in val:
            out += _flatten(v)
        return out
    return []


def _sub_values(val, ctx: dict | None) -> list[str]:
    """All subject patterns a condition value can produce, resolved from the file."""
    raw = _flatten(val)
    if any("repo:" in r for r in raw):  # drop !If condition names etc.
        raw = [r for r in raw if "repo:" in r or r.startswith(EXPR)]
    out = []
    for r in raw:
        r = r.strip()
        if r.startswith("repo:"):
            out.append(r)
            continue
        resolved = _expand(r, ctx or {})
        out += resolved if resolved else [r]
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------------------
# Subject grading (codebook rules 2 and 3)
# ---------------------------------------------------------------------------

_ID_SUFFIX = re.compile(r'@(\d+|\*|\x00)')


def _repo_shape(rp: str) -> tuple[str, str]:
    """Rung implied by the owner/repo part alone (S0, S1, or S2 = pinned)."""
    rp = _ID_SUFFIX.sub("", rp)  # immutable-subject ids, including @*, never widen names
    if rp in ("", "*"):
        return "S0", "wildcard/empty repo spec admits every organization"
    if "/" in rp:
        owner, repo = rp.split("/", 1)
        if owner == "*":
            return "S0", "wildcard in the owner position admits every organization"
        if "*" in owner:
            return "S0", ("prefix wildcard on the owner admits any organization whose "
                          "name matches, and anyone can register one")
        if repo in ("", "*"):
            return "S1", "organization wildcard admits any repo in the org"
        if "*" in repo:
            return "S1", "partial wildcard in the repo position admits unnamed repos"
        return "S2", "repo pinned"
    if "*" in rp:
        return "S1", "wildcard in an interpolated repo spec"
    return "S2", "repo pinned via interpolation"


def _context_rung(ctx: str) -> tuple[str, str]:
    """Rung implied by what follows owner/repo (rule 2: a '*' anywhere in the
    ref or environment means anyone with write access can satisfy it)."""
    if ctx in ("", "*"):
        return "S2", "ref unconstrained: any branch or tag"
    if ctx.replace("\x00", "") == "":
        return "U1", "context is an unresolved value"
    head, _, val = ctx.partition(":")
    if head == "environment":
        if "*" in val or not val:
            return "S2", ("wildcard environment: any writer can run in a matching "
                          "environment (GitHub creates referenced environments on demand)")
        return "S4", "environment-pinned; GitHub-side approval gates available"
    if head == "ref":
        if "*" in val or not val:
            return "S2", "wildcard ref: any writer can push a matching branch or tag"
        return "S3", "repo and ref pinned"
    if head == "pull_request":
        return "S3", "pull_request context pinned"
    if head == "workflow":
        return "S3", "reusable-workflow context pinned"
    if "*" in ctx:
        return "S2", "wildcard context"
    return "S3", "specific context pinned"


def _classify_sub(pattern: str) -> tuple[str, str, str]:
    """Return (rung, sub_format, reason) for one sub pattern.

    The owner/repo part caps the rung (S0/S1 admit other repos whatever follows);
    when the repo is pinned, the context after it (ref, environment,
    pull_request) decides. Interpolations are placeholders for named values, so
    `repo:${var.repo}:environment:prod` is S4.
    """
    raw = pattern.strip().strip('"\'`')
    if raw.startswith(EXPR):
        return "U1", "none", "sub is an expression that cannot be resolved from the file"
    if BARE_REF.match(raw) or raw == "\x00" or _placeholder(raw) == "\x00":
        return "U1", "none", "sub value is entirely an unresolved reference"
    if not raw.startswith("repo:"):
        return "U1", "none", f"sub does not use the repo: form: {raw[:80]!r}"

    body = raw[len("repo:"):]
    fmt = _fmt(body)
    ph = _placeholder(body)
    repo_part, _, context = ph.partition(":")
    r_rung, r_why = _repo_shape(repo_part)
    if r_rung in ("S0", "S1"):
        return r_rung, ("none" if r_rung == "S0" else fmt), r_why
    c_rung, c_why = _context_rung(context)
    if c_rung == "U1":
        return "U1", "none", c_why
    why = c_why if c_rung != "S2" or context not in ("", "*") else \
        ("repo pinned, ref unconstrained: any branch or tag" if "/" in repo_part
         else "repo pinned via interpolation, ref unconstrained")
    return c_rung, fmt, why


def _iter_conditions(cond: Any):
    """Yield (claim_key, raw_value) across every condition operator."""
    if not isinstance(cond, dict):
        return
    for _operator, mapping in cond.items():
        if not isinstance(mapping, dict):
            continue
        for key, val in mapping.items():
            yield key, val


def classify_statement(stmt: dict, ctx: dict | None = None) -> Coding | None:
    """Code one trust-policy statement, or None if it is not a web-identity grant.
    ctx = {"text": file text, "params": CloudFormation parameter defaults} lets
    non-literal sub values be resolved from the same file (rule 1)."""
    actions = stmt.get("Action", [])
    actions = actions if isinstance(actions, list) else [actions]
    if not any("AssumeRoleWithWebIdentity" in str(a) for a in actions):
        return None

    principal = stmt.get("Principal", {})
    federated = principal.get("Federated", "") if isinstance(principal, dict) else ""
    # Federated may be a list, and its items may be CloudFormation intrinsics
    # rendered as dicts/lists (!GetAtt, !Sub, Fn::Sub). Stringify each item so a
    # dict does not crash join and the issuer text inside it is still searchable.
    if isinstance(federated, list):
        federated = " ".join(str(x) for x in federated)
    else:
        federated = str(federated)

    cond = stmt.get("Condition", {})
    claim_keys = [str(k) for k, _ in _iter_conditions(cond)]

    is_github = GH_ISSUER in federated or any(GH_ISSUER in k for k in claim_keys)
    if not is_github:
        return Coding("U3", False, "none", "issuer is not the GitHub Actions OIDC provider")

    aud_constrained = False
    sub_patterns: list[str] = []
    sub_key_seen = False
    jwr_values: list[str] = []
    has_repo_property = False

    for key, val in _iter_conditions(cond):
        key = str(key)
        if GH_ISSUER not in key:
            continue
        claim = key[len(GH_ISSUER) + 1:] if key.startswith(GH_ISSUER + ":") else key.rsplit(":", 1)[-1]
        if claim == "aud":
            aud_constrained = True
        elif claim == "sub":
            sub_key_seen = True
            sub_patterns.extend(_sub_values(val, ctx))
        elif claim == "job_workflow_ref":
            jwr_values.extend(_flatten(val))
        elif claim.startswith("repo_property_"):
            has_repo_property = True

    if has_repo_property:
        return Coding("U1", aud_constrained, "none",
                      "repo_property_* ABAC condition: admitted set is defined outside the repo",
                      sub_patterns)

    # A job_workflow_ref pinned to one workflow file at a literal ref (no '*')
    # binds the token to that workflow whatever the sub says.
    jwr_pinned = bool(jwr_values) and all(
        "*" not in _placeholder(v) and not v.startswith(EXPR) and "/" in v for v in jwr_values)

    if not sub_patterns:
        if jwr_pinned:
            return Coding("S4", aud_constrained, "historical",
                          "constrained on job_workflow_ref: pins the reusable workflow identity")
        if sub_key_seen:
            return Coding("U1", aud_constrained, "none",
                          "sub condition present but its value is empty or unreadable")
        return Coding("S0", aud_constrained, "none",
                      "no sub condition; aud is the same constant for every GitHub user")

    results = [_classify_sub(p) for p in sub_patterns]
    rungs = [r for r, _, _ in results]

    if jwr_pinned:
        return Coding("S4", aud_constrained,
                      next((f for _, f, _ in results if f != "none"), "historical"),
                      "job_workflow_ref pinned to one workflow at a literal ref", sub_patterns)

    if all(r == "U1" for r in rungs):
        return Coding("U1", aud_constrained, "none", results[0][2], sub_patterns)

    # Unresolvable patterns are left out of the loosest-wins rule. That can only
    # make the reported rung TIGHTER than the truth, so loose-trust prevalence is
    # a lower bound.
    codeable = [(r, f, why) for r, f, why in results if r != "U1"]
    rung = _loosest([r for r, _, _ in codeable])
    why = next(w for r, _, w in codeable if r == rung)

    formats = {f for _, f, _ in codeable if f != "none"}
    sub_format = formats.pop() if len(formats) == 1 else ("mixed" if formats else "none")

    return Coding(rung, aud_constrained, sub_format, why, sub_patterns)


def _walk_for_policies(obj: Any, out: list):
    """Collect anything that looks like a policy document with a Statement list."""
    if isinstance(obj, dict):
        if "Statement" in obj and isinstance(obj["Statement"], (list, dict)):
            out.append(obj)
        for v in obj.values():
            _walk_for_policies(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _walk_for_policies(v, out)


class _HclParser:
    """
    Recursive-descent parser for the HCL object-expression subset that appears
    inside jsonencode(...).

    Why not regex: HCL makes entry separators optional (newline OR comma),
    allows bare identifier keys at any nesting depth, and permits unquoted
    references as values. A regex chain gets each of those wrong in a
    different way. This is ~80 lines and handles all of them.

    References (var.x, local.y) and heredocs are preserved as "${...}" strings
    so the shape-vs-U1 decision stays available downstream.
    """

    def __init__(self, text: str):
        self.s = text
        self.i = 0

    def _ws(self):
        while self.i < len(self.s):
            c = self.s[self.i]
            if c in " \t\r\n,":
                self.i += 1
            elif c == "#" or (c == "/" and self.s[self.i:self.i + 2] == "//"):
                while self.i < len(self.s) and self.s[self.i] != "\n":
                    self.i += 1
            elif self.s[self.i:self.i + 2] == "/*":
                end = self.s.find("*/", self.i)
                self.i = len(self.s) if end == -1 else end + 2
            else:
                return

    def _string(self) -> str:
        quote = self.s[self.i]
        self.i += 1
        out = []
        while self.i < len(self.s):
            c = self.s[self.i]
            if c == "\\":
                out.append(self.s[self.i:self.i + 2])
                self.i += 2
                continue
            if c == quote:
                self.i += 1
                break
            # Keep ${...} interpolations intact, including nested braces
            if self.s[self.i:self.i + 2] == "${":
                depth, j = 0, self.i + 1
                while j < len(self.s):
                    if self.s[j] == "{":
                        depth += 1
                    elif self.s[j] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                out.append(self.s[self.i:j + 1])
                self.i = j + 1
                continue
            out.append(c)
            self.i += 1
        return "".join(out)

    def _bare(self) -> str:
        start = self.i
        while self.i < len(self.s):
            c = self.s[self.i]
            if c.isalnum() or c in "_-.*]":
                self.i += 1
            elif c == "[" and self.i > start:
                # Index/subscript on a reference: local.roles["scaling-role"], x[0].
                # Consume it whole (string-aware) so the reference stays one token.
                depth, j, in_str = 0, self.i, False
                while j < len(self.s):
                    ch = self.s[j]
                    if in_str:
                        in_str = ch != '"'
                    elif ch == '"':
                        in_str = True
                    elif ch == "[":
                        depth += 1
                    elif ch == "]":
                        depth -= 1
                        if depth == 0:
                            break
                    elif ch == "\n":
                        break
                    j += 1
                self.i = j + 1 if j < len(self.s) and self.s[j] == "]" else j
            elif c == "[":
                self.i += 1
            else:
                break
        return self.s[start:self.i]

    def _balanced(self) -> str:
        """Consume a balanced (...) starting at self.i; return its text."""
        start, depth, in_str = self.i, 0, False
        while self.i < len(self.s):
            c = self.s[self.i]
            if in_str:
                if c == "\\":
                    self.i += 1
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    self.i += 1
                    break
            self.i += 1
        return self.s[start:self.i]

    def _value(self):
        self._ws()
        if self.i >= len(self.s):
            return None
        c = self.s[self.i]
        if c == "(":
            # Parenthesized expression, e.g. a ternary: keep it whole for rule-1
            # resolution instead of dropping it (dropping it read as "no sub").
            return EXPR + self._balanced()
        if c == "{":
            return self._object()
        if c == "[":
            return self._array()
        if c in "\"'":
            return self._string()
        tok = self._bare()
        if tok and self.i < len(self.s) and self.s[self.i] == "(":
            return EXPR + tok + self._balanced()  # function call: format(...), concat(...)
        if tok and tok not in ("true", "false", "null"):
            # A trailing ternary or operator: `var.x ? "a" : "b"`. Keep the rest
            # of the expression (to end of line) so its strings stay visible.
            j = self.i
            while j < len(self.s) and self.s[j] in " \t":
                j += 1
            if j < len(self.s) and self.s[j] in "?=!<>&|":
                end = self.s.find("\n", j)
                end = len(self.s) if end == -1 else end
                expr = tok + self.s[self.i:end]
                self.i = end
                return EXPR + expr
        if not tok:
            # Unrecognized character in value position: '(' from a function call
            # like format(...), '<' from a heredoc, '?' from a ternary, etc.
            # Skip exactly one char so the CALLER always makes progress. Without
            # this, an array/object loop spins forever on such input -- the
            # infinite loop real-world .tf files triggered.
            self.i += 1
            return None
        if tok in ("true", "false"):
            return tok == "true"
        if tok == "null":
            return None
        try:
            return float(tok) if "." in tok else int(tok)
        except ValueError:
            # A reference such as var.repo_name -- keep it as an interpolation
            return "${" + tok + "}"

    def _array(self) -> list:
        self.i += 1  # consume [
        out = []
        while True:
            self._ws()
            if self.i >= len(self.s):
                break
            if self.s[self.i] == "]":
                self.i += 1
                break
            before = self.i
            out.append(self._value())
            if self.i == before:  # progress guarantee: never spin in place
                self.i += 1
        return out

    def _object(self) -> dict:
        self.i += 1  # consume {
        out = {}
        while True:
            self._ws()
            if self.i >= len(self.s):
                break
            if self.s[self.i] == "}":
                self.i += 1
                break
            before = self.i
            key = self._string() if self.s[self.i] in "\"'" else self._bare()
            if not key:
                self.i += 1
                continue
            self._ws()
            if self.i < len(self.s) and self.s[self.i] in "=:":
                self.i += 1
            out[key] = self._value()
            if self.i == before:  # progress guarantee
                self.i += 1
        return out

    def parse(self):
        return self._value()


def _extract_json_policies_from_hcl(text: str) -> list[dict]:
    """Pull every assume_role_policy = jsonencode({...}) body out of HCL."""
    policies = []
    for m in re.finditer(r"jsonencode\s*\(", text):
        start = text.index("(", m.start())
        depth, i = 0, start
        while i < len(text):
            if text[i] in "({[":
                depth += 1
            elif text[i] in ")}]":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = text[start + 1:i]
        try:
            parsed = _HclParser(body).parse()
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            policies.append(parsed)
        else:
            policies.append({"__unparsed__": body, "Statement": []})
    return policies


def _brace_body(s: str, open_idx: int) -> str:
    """Return the text inside a { } starting at open_idx (the '{'), brace-matched."""
    depth, i = 0, open_idx
    while i < len(s):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return s[open_idx + 1:i]
        i += 1
    return s[open_idx + 1:]


def _hcl_list(body: str, key: str) -> list[str]:
    """Extract the quoted strings from `key = [ ... ]`, or `key = "x"`."""
    m = re.search(rf'\b{key}\s*=\s*\[(.*?)\]', body, re.DOTALL)
    if m:
        return re.findall(r'"([^"]*)"', m.group(1))
    m = re.search(rf'\b{key}\s*=\s*"([^"]*)"', body)
    return [m.group(1)] if m else []


def _hcl_values(body: str) -> list[str]:
    """`values = ...` in a condition block. A literal list of strings comes back
    as those strings; anything else (local.x, [local.x], concat(...), a for
    expression) comes back as one EXPR for rule-1 resolution."""
    m = re.search(r'\bvalues\s*=\s*', body)
    if not m:
        return []
    rhs = _rhs_extent(body, m.end()).strip()
    if rhs.startswith("["):
        inner = rhs[1:-1] if rhs.endswith("]") else rhs[1:]
        strings = _quoted_strings(inner)
        leftover = re.sub(r'"(?:[^"\\]|\\.)*"', "", inner)
        if strings and not re.search(r'[A-Za-z_]', re.sub(r'\$\{[^}]*\}', "", leftover)):
            return strings
    if rhs.startswith('"') and rhs.endswith('"'):
        return _quoted_strings(rhs)
    return [EXPR + rhs]


def _hcl_scalar(body: str, key: str) -> str | None:
    m = re.search(rf'\b{key}\s*=\s*"([^"]*)"', body)
    return m.group(1) if m else None


def _extract_native_policy_documents(text: str) -> list[dict]:
    """
    Extract trust policies written as `data "aws_iam_policy_document"` blocks
    (the HCL-native idiom, ~21% of the files the jsonencode-only extractor missed).

    Each statement's repeated `condition { test/variable/values }` sub-blocks are
    collected into the canonical Condition dict so they flow through
    classify_statement unchanged -- multiple conditions must not collapse.
    """
    policies = []
    for dm in re.finditer(r'data\s+"aws_iam_policy_document"\s+"[^"]*"\s*\{', text):
        block = _brace_body(text, dm.end() - 1)
        statements = []
        for sm in re.finditer(r'\bstatement\s*\{', block):
            sbody = _brace_body(block, sm.end() - 1)
            actions = _hcl_list(sbody, "actions")

            federated = []
            for pm in re.finditer(r'\bprincipals\s*\{', sbody):
                federated += _hcl_list(_brace_body(sbody, pm.end() - 1), "identifiers")

            cond: dict = {}
            for cm in re.finditer(r'\bcondition\s*\{', sbody):
                cbody = _brace_body(sbody, cm.end() - 1)
                test = _hcl_scalar(cbody, "test")
                var = _hcl_scalar(cbody, "variable")
                vals = _hcl_values(cbody)
                if not var:
                    continue
                if not test:
                    # Operator chosen by an expression, e.g.
                    # `test = each.key == "apply" ? "StringEquals" : "StringLike"`.
                    # The operator does not change the admitted shape we grade, so
                    # keep the condition rather than dropping it (dropping it read
                    # as "no sub", i.e. S0).
                    test = "StringLike"
                # Normalize an interpolated claim-key prefix to the literal issuer
                # so downstream detection works. Real files write the variable as
                # "${local.oidc_claim_prefix}:sub" where the local resolves to the
                # GitHub issuer; only normalize in a GitHub context.
                if (var.endswith(":sub") or var.endswith(":aud")) and GH_ISSUER not in var:
                    claim = var.rsplit(":", 1)[1]
                    vlist = vals if isinstance(vals, list) else [vals]
                    if GH_ISSUER in text or any(str(v).startswith("repo:") for v in vlist):
                        var = f"{GH_ISSUER}:{claim}"
                cond.setdefault(test, {})[var] = vals if len(vals) != 1 else vals[0]

            references_github = any(GH_ISSUER in k for grp in cond.values() for k in grp) \
                or any(GH_ISSUER in idn for idn in federated)
            has_action = any("AssumeRoleWithWebIdentity" in a for a in actions)
            if not (has_action or references_github):
                continue
            # Ensure the action is present so classify_statement proceeds even
            # when identifiers/actions are resource references rather than literals.
            if not has_action:
                actions = list(actions) + ["sts:AssumeRoleWithWebIdentity"]
            statements.append({
                "Effect": "Allow",
                "Action": actions,
                "Principal": {"Federated": federated},
                "Condition": cond,
            })
        if statements:
            policies.append({"Statement": statements})
    return policies


# The GitHub subject signature: a sub value always begins `repo:owner/...`.
# This is what we scan for when the claim key is interpolated and the literal
# issuer never sits next to `:sub` (CDK/Pulumi/SST, dynamic jsonencode, plan JSON).
_SUB_SIGNATURE = re.compile(r'repo:[A-Za-z0-9_.${}][A-Za-z0-9_.${}/*@:-]*')

_BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)
_LINE_COMMENT = re.compile(r'(?m)(?:(?<=\s)|^)(#|//).*$')


def _strip_comments(text: str) -> str:
    """
    Remove comments before the salvage subject-scan so a looser example in a
    comment (e.g. `// do NOT use repo:org/*`) cannot beat the real rule. Trust
    values live in string literals, never in comments, so this only removes
    noise. The negative-lookbehind on '//' leaves `https://` URLs intact.
    """
    text = _BLOCK_COMMENT.sub(" ", text)
    return _LINE_COMMENT.sub("", text)
# Claim keys, tolerating an escaping backslash before the quote (plan JSON: :aud\")
_CDK_WEB_IDENTITY = re.compile(r'\b(OpenIdConnectPrincipal|WebIdentityPrincipal|FederatedPrincipal)\b')
_ASSERTION = re.compile(r'\bassert(?:\.\w+)?\s*\(|\bexpect\s*\(')
_AUD_KEY = re.compile(r':aud\\?["\'`]')     # a `<prefix>:aud"` claim key, prefix may be interpolated
_SUB_KEY = re.compile(r':sub\\?["\'`]')     # a `<prefix>:sub"` claim key


def _salvage_from_text(text: str) -> Coding | None:
    """
    Last-resort text scan, for AWS GitHub web-identity trusts the structural
    parsers cannot read: interpolated claim-key prefixes, dynamic jsonencode
    (for-loops, ternaries), CDK/Pulumi/SST TypeScript, plan output.

    Detects the trust by the `repo:owner/...` subject signature rather than the
    literal issuer claim key. Requires a real trust-DEFINING signal (an aud/sub
    claim key or a github federated-principal ARN) so that files which only
    MENTION the issuer -- workflow YAML, comments -- are not miscoded. Codes by
    the loosest sub (admitted population is the union) and flags the row salvaged.
    """
    # Scan comment-free text so a looser example in a comment cannot win, and so
    # a file that only MENTIONS the issuer in comments falls through to U3.
    scan = _strip_comments(text)
    cdk_principal = _CDK_WEB_IDENTITY.search(scan) is not None
    if ("AssumeRoleWithWebIdentity" not in scan and not cdk_principal) or GH_ISSUER not in scan:
        return None  # AWS web-identity + GitHub issuer must both be present in code

    # Not policy definitions: the IAM service-authorization reference (lists every
    # condition key) and test/assertion code that checks a policy built elsewhere.
    if '"ActionConditionKeys"' in scan or '"ConditionKeys"' in scan:
        return None
    if len(_ASSERTION.findall(scan)) >= 2:
        return Coding("U3", False, "none",
                      "test/assertion code about a trust policy, not a policy definition")

    has_aud = _AUD_KEY.search(scan) is not None
    has_sub_key = _SUB_KEY.search(scan) is not None
    has_fed = ("oidc-provider/" + GH_ISSUER) in scan
    if not (has_aud or has_sub_key or has_fed or cdk_principal):
        return None  # issuer only incidental (e.g. a workflow referencing a role)

    subs = list(dict.fromkeys(m.group(0) for m in _SUB_SIGNATURE.finditer(scan)))
    if not subs:
        if has_sub_key:
            # The sub is built by code (a function call, .join, a helper): it exists
            # but its shape is not in the file. That is U1, never "no sub" (S0).
            return Coding("U1", has_aud, "none",
                          "salvaged (text scan): sub condition built by code, shape not in file")
        return Coding("S0", has_aud, "none",
                      "salvaged (text scan): web-identity trust with no sub condition")

    results = [_classify_sub(s) for s in subs]
    codeable = [(r, f, w) for r, f, w in results if r != "U1"]
    if not codeable:
        return Coding("U1", has_aud, "none", "salvaged (text scan): sub unresolved", subs)

    rung = _loosest([r for r, _, _ in codeable])
    fmts = {f for _, f, _ in codeable if f != "none"}
    fmt = fmts.pop() if len(fmts) == 1 else ("mixed" if fmts else "none")
    why = next(w for r, _, w in codeable if r == rung)
    return Coding(rung, has_aud, fmt, "salvaged (text scan): " + why, subs)


def classify_file(path: Path) -> Coding:
    # utf-8-sig strips a leading UTF-8 BOM (which some Windows editors add and
    # which otherwise breaks json.loads); it is a no-op on files without one.
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    suffix = path.suffix.lower()
    cfn_defaults: dict = {}

    if suffix in {".json", ".yaml", ".yml"}:
        if suffix == ".json":
            doc = json.loads(text)
        else:
            try:
                import yaml
            except ImportError:
                return Coding("U1", False, "none",
                              "YAML file skipped: pyyaml not installed "
                              "(pip install pyyaml to include CloudFormation YAML)")
            # CloudFormation YAML uses intrinsic tags (!Ref, !Sub, !GetAtt) that
            # safe_load rejects. Render any unknown tag as its raw scalar/sequence
            # so the surrounding policy structure stays readable.
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
                doc = yaml.load(text, Loader=_CfnLoader)
            except yaml.YAMLError as e:
                return Coding("U1", False, "none", f"YAML parse failed: {str(e)[:120]}")
        policies: list = []
        _walk_for_policies(doc, policies)
        params = doc.get("Parameters") if isinstance(doc, dict) else None
        if isinstance(params, dict):
            cfn_defaults = {k: v.get("Default") for k, v in params.items()
                            if isinstance(v, dict) and v.get("Default") not in (None, "")}
    else:
        policies = _extract_json_policies_from_hcl(text)
        policies += _extract_native_policy_documents(text)

    codings = []
    for pol in policies:
        stmts = pol.get("Statement", [])
        stmts = stmts if isinstance(stmts, list) else [stmts]
        for stmt in stmts:
            if not isinstance(stmt, dict):
                continue
            c = classify_statement(stmt, {"text": text, "params": cfn_defaults})
            if c is not None:
                codings.append(c)

    github = [c for c in codings if c.rung != "U3"]
    if github:
        rungs = [c.rung for c in github if c.rung != "U1"]
        if not rungs:
            return github[0]
        target = _loosest(rungs)
        return next(c for c in github if c.rung == target)

    # No structured GitHub coding: try the text-salvage fallback before U3.
    salvaged = _salvage_from_text(text)
    if salvaged is not None:
        return salvaged

    if codings:
        return codings[0]
    return Coding("U3", False, "none", "no sts:AssumeRoleWithWebIdentity statement found")


if __name__ == "__main__":
    import sys
    for arg in sys.argv[1:]:
        print(arg, json.dumps(classify_file(Path(arg)).as_dict()))
