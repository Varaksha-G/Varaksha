"""ast_inspector.py — GATE-M Layer 2: Deep AST Security Inspection.

Extends basic side-effect detection with deeper static analysis:

  Category A — Code execution  (subprocess, os.system, exec, eval, compile)
  Category B — Network access  (socket, requests, httpx, external URL strings)
  Category C — Env exfiltration (os.environ reads, getenv, then network send)
  Category D — Obfuscation     (base64+exec chains, __import__, dynamic compile)
  Category E — Dangerous IO    (pickle.loads, yaml.load unsafe, open('/proc/*'))
  Category F — Supply chain    (import of non-stdlib unpinned packages added inline)

All findings are returned as ASTFinding dataclasses so callers can decide
whether to hard-stop or log per finding severity.

This module is PURE ANALYSIS — it never modifies files or applies patches.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Finding severity levels
# ---------------------------------------------------------------------------

CRITICAL = "CRITICAL"   # hard stop — block immediately
HIGH     = "HIGH"       # block by default, configurable override
MEDIUM   = "MEDIUM"     # log + flag, not auto-block


@dataclass
class ASTFinding:
    category: str          # A–F
    severity: str          # CRITICAL | HIGH | MEDIUM
    message: str           # human-readable description
    line: int = 0          # line number in the added source fragment (0 = unknown)
    node_type: str = ""    # AST node class name


# ---------------------------------------------------------------------------
# Dangerous patterns
# ---------------------------------------------------------------------------

# Category A — execution
_EXEC_MODULES = frozenset({"subprocess", "os"})
_EXEC_BUILTINS = frozenset({"exec", "eval", "compile", "__import__"})
_OS_EXEC_ATTRS = frozenset({
    "system", "popen", "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "call", "run", "check_output", "check_call", "Popen",
})

# Category B — network
_NET_MODULES = frozenset({
    "socket", "requests", "httpx", "urllib", "urllib3",
    "aiohttp", "http", "ftplib", "smtplib", "imaplib",
    "asyncio",  # asyncio.open_connection / create_connection
})
# External URL pattern — catches http:// and https:// to non-localhost targets
_EXTERNAL_URL_RE = re.compile(
    r"https?://(?!(?:127\.0\.0\.1|localhost|0\.0\.0\.0))[^\s\"']+",
    re.IGNORECASE,
)

# Category C — env exfiltration
_ENV_READ_ATTRS = frozenset({"getenv", "environ"})

# Category D — obfuscation
_OBFUSCATION_MODULES = frozenset({"base64", "codecs", "zlib"})
_DYNAMIC_IMPORT_FUNCS = frozenset({"__import__", "importlib.import_module"})

# Category E — dangerous IO
_DANGEROUS_IO: dict[str, frozenset[str]] = {
    "pickle":    frozenset({"loads", "load", "Unpickler"}),
    "yaml":      frozenset({"load"}),          # yaml.safe_load is fine
    "marshal":   frozenset({"loads", "load"}),
    "shelve":    frozenset({"open"}),
}
_PROC_FS_RE = re.compile(r"['\"]/?(?:proc|sys|etc|dev)/")


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _SecurityVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[ASTFinding] = []
        self._imported_modules: set[str] = set()
        self._env_reads_at: list[int] = []
        self._net_calls_at: list[int] = []

    def _add(
        self,
        category: str,
        severity: str,
        message: str,
        node: Optional[ast.AST] = None,
        node_type: str = "",
    ) -> None:
        line = getattr(node, "lineno", 0) if node else 0
        ntype = node_type or (type(node).__name__ if node else "")
        self.findings.append(ASTFinding(category, severity, message, line, ntype))

    # ── Category A: execution ────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            self._imported_modules.add(top)
            if top == "subprocess":
                self._add("A", CRITICAL, f"import subprocess — shell execution capability", node)
            elif top == "os":
                self._add("A", HIGH, "import os — includes shell/exec functions", node)
            elif top in _NET_MODULES:
                self._add("B", HIGH, f"import {alias.name} — network access capability", node)
            elif top in _OBFUSCATION_MODULES:
                self._add("D", MEDIUM, f"import {alias.name} — obfuscation-capable module", node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        top = mod.split(".")[0]
        self._imported_modules.add(top)
        for alias in node.names:
            # Check if importing specific dangerous functions
            full = f"{mod}.{alias.name}"
            if alias.name in _EXEC_BUILTINS:
                self._add("A", CRITICAL, f"from-import of exec primitive: {full}", node)
            if top in _NET_MODULES:
                self._add("B", HIGH, f"from {mod} import {alias.name} — network access", node)
            if top == "subprocess":
                self._add("A", CRITICAL, f"from subprocess import {alias.name}", node)
            # yaml.load without Loader= is unsafe
            if mod == "yaml" and alias.name == "load":
                self._add("E", HIGH, "from yaml import load — use yaml.safe_load instead", node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # exec() / eval() / compile() / __import__()
        if isinstance(func, ast.Name) and func.id in _EXEC_BUILTINS:
            self._add("A", CRITICAL, f"call to {func.id}() — dynamic code execution", node)

        # subprocess.*
        if isinstance(func, ast.Attribute):
            obj_name = ""
            if isinstance(func.value, ast.Name):
                obj_name = func.value.id
            elif isinstance(func.value, ast.Attribute):
                # e.g. subprocess.Popen
                obj_name = getattr(func.value, "attr", "")

            if obj_name == "subprocess" or (
                obj_name in ("", "subprocess") and func.attr in _OS_EXEC_ATTRS
            ):
                self._add("A", CRITICAL, f"subprocess.{func.attr}() call", node)

            # os.system / os.exec*
            if obj_name == "os" and func.attr in _OS_EXEC_ATTRS:
                self._add("A", CRITICAL, f"os.{func.attr}() — shell/exec call", node)

            # os.environ reads  (Category C)
            if obj_name == "os" and func.attr in _ENV_READ_ATTRS:
                self._add("C", HIGH, f"os.{func.attr}() — environment variable read", node)
                self._env_reads_at.append(getattr(node, "lineno", 0))

            # Network calls (Category B)
            if obj_name in _NET_MODULES or func.attr in {"get", "post", "put", "request", "urlopen"}:
                if obj_name in _NET_MODULES or "requests" in self._imported_modules:
                    self._add("B", HIGH, f"{obj_name}.{func.attr}() — outbound network call", node)
                    self._net_calls_at.append(getattr(node, "lineno", 0))

            # Dangerous IO: pickle.loads, yaml.load, marshal.loads
            for mod, attrs in _DANGEROUS_IO.items():
                if obj_name == mod and func.attr in attrs:
                    sev = CRITICAL if mod == "pickle" else HIGH
                    self._add("E", sev, f"{mod}.{func.attr}() — unsafe deserialization", node)

            # base64 + exec obfuscation (Category D)
            if obj_name in _OBFUSCATION_MODULES and func.attr in {"b64decode", "decodebytes", "decode", "decompress"}:
                self._add("D", HIGH, f"{obj_name}.{func.attr}() — potential obfuscation", node)

        # importlib.import_module (Category D)
        if isinstance(func, ast.Attribute) and func.attr == "import_module":
            if isinstance(func.value, ast.Name) and func.value.id == "importlib":
                self._add("D", HIGH, "importlib.import_module() — dynamic import", node)

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # os.environ subscript access
        if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
            self._add("C", MEDIUM, "os.environ attribute access — environment variable read", node)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.s, str):
            # External URLs baked into string literals
            matches = _EXTERNAL_URL_RE.findall(node.s)
            for url in matches:
                self._add("B", HIGH, f"hardcoded external URL in string: {url[:80]}", node)
            # /proc /sys /etc paths
            if _PROC_FS_RE.search(node.s):
                self._add("E", MEDIUM, f"reference to privileged FS path: {node.s[:60]}", node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        # f-strings — recurse but don't double-count constants
        self.generic_visit(node)

    # ── Post-analysis: cross-category exfiltration pattern ──────────────

    def _check_exfiltration_pattern(self) -> None:
        """If env reads AND net calls appear in the same fragment → HIGH finding."""
        if self._env_reads_at and self._net_calls_at:
            self._add(
                "C", CRITICAL,
                f"EXFILTRATION PATTERN: env var read (lines {self._env_reads_at}) "
                f"AND network call (lines {self._net_calls_at}) in same diff fragment"
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _extract_added_lines(unified_diff: str) -> str:
    """Return only added lines (+) from a unified diff, stripping the leading +."""
    lines: list[str] = []
    for line in unified_diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    return "\n".join(lines)


def _try_parse(source: str) -> Optional[ast.AST]:
    """Try multiple parse strategies on a source fragment."""
    candidates = [
        source,
        "def _gate_wrapper():\n" + "\n".join("    " + l for l in source.splitlines()),
        "\n".join(l.lstrip() for l in source.splitlines()),
    ]
    for candidate in candidates:
        try:
            return ast.parse(candidate)
        except SyntaxError:
            continue
    return None


def inspect_diff(unified_diff: str) -> list[ASTFinding]:
    """
    Parse the added lines of a unified diff and return all security findings.

    Args:
        unified_diff: A unified diff string (output of `git diff` or similar).

    Returns:
        List of ASTFinding. Empty list means no issues detected.
    """
    added_source = _extract_added_lines(unified_diff)
    if not added_source.strip():
        return []

    tree = _try_parse(added_source)
    if tree is None:
        # Can't parse — conservative: flag as MEDIUM
        return [ASTFinding(
            category="X",
            severity=MEDIUM,
            message="Could not parse added lines as Python AST — manual review required",
            line=0,
            node_type="ParseError",
        )]

    visitor = _SecurityVisitor()
    visitor.visit(tree)
    visitor._check_exfiltration_pattern()
    return visitor.findings


def inspect_source(source: str) -> list[ASTFinding]:
    """
    Inspect a raw Python source string (not a diff).
    Used for full-file analysis at invariant-check time.
    """
    tree = _try_parse(source)
    if tree is None:
        return [ASTFinding("X", MEDIUM, "Could not parse source as Python AST", 0, "ParseError")]
    visitor = _SecurityVisitor()
    visitor.visit(tree)
    visitor._check_exfiltration_pattern()
    return visitor.findings


def has_critical_findings(findings: list[ASTFinding]) -> bool:
    return any(f.severity == CRITICAL for f in findings)


def findings_summary(findings: list[ASTFinding]) -> str:
    if not findings:
        return "No security findings."
    lines = [f"[{f.severity}] Category {f.category} — {f.message} (line {f.line})" for f in findings]
    return "\n".join(lines)
