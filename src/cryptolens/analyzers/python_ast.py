from __future__ import annotations

import ast
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from cryptolens.analyzers.symbol_table import (
    Binding,
    BindingKind,
    SymbolTable,
    SymbolTableWalker,
    dotted_parts,
    package_from_path,
)
from cryptolens.model import SourceLocation

logger = logging.getLogger(__name__)

CONFIDENCE_DYNAMIC = 0.2
MAX_RAW_LENGTH = 120
STARRED_KWARG_KEY = "**"

BUILTINS_OF_INTEREST = frozenset(
    {"eval", "exec", "compile", "getattr", "setattr", "open", "__import__"}
)

_LITERAL_FAILURES = (ValueError, TypeError, SyntaxError, MemoryError, RecursionError)
_UNPARSE_FAILURES = (ValueError, TypeError, AttributeError, RecursionError)
_PARSE_FAILURES = (SyntaxError, ValueError, MemoryError, RecursionError)


class ArgKind(str, Enum):
    LITERAL = "literal"
    NAME = "name"
    CALL = "call"
    ATTRIBUTE = "attribute"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class ArgValue:
    kind: ArgKind
    raw: str
    value: Any | None = None
    resolved_name: str | None = None


@dataclass
class RawSymbolUsage:
    resolved_name: str | None
    location: SourceLocation
    raw: str
    args: list[ArgValue] = field(default_factory=list)
    kwargs: dict[str, ArgValue] = field(default_factory=dict)
    confidence: float = 1.0
    parent_name: str | None = None
    node: ast.Call | None = field(default=None, repr=False, compare=False)

    @property
    def is_dynamic(self) -> bool:
        return self.resolved_name is None


def snippet(node: ast.AST) -> str:
    try:
        text = ast.unparse(node)
    except _UNPARSE_FAILURES:
        return "<unparseable>"
    text = " ".join(text.split())
    if len(text) > MAX_RAW_LENGTH:
        return text[: MAX_RAW_LENGTH - 3] + "..."
    return text


class PythonAstAnalyzer(SymbolTableWalker):
    def __init__(self, table: SymbolTable, file: str) -> None:
        super().__init__(table)
        self.file = file
        self.usages: list[RawSymbolUsage] = []
        self._parents: list[str | None] = []

    def visit_Call(self, node: ast.Call) -> None:
        emitted = self._record(node)
        self._parents.append(emitted[0].resolved_name if emitted else None)
        self.generic_visit(node)
        self._parents.pop()

    def _target_bindings(self, func: ast.AST) -> tuple[list[Binding], bool]:
        parts = dotted_parts(func)
        if parts is not None:
            bindings = self.table.resolve(parts)
            if bindings:
                return bindings, False
            if len(parts) == 1 and parts[0] in BUILTINS_OF_INTEREST:
                return [Binding(parts[0])], False
            return [], False
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call):
            receiver, _ = self._target_bindings(func.value.func)
            if receiver:
                return [
                    Binding(
                        f"{b.qualified_name}.{func.attr}",
                        BindingKind.INSTANCE,
                        b.confidence,
                    )
                    for b in receiver
                ], False
        return [], True

    def _record(self, node: ast.Call) -> list[RawSymbolUsage]:
        common = {
            "location": SourceLocation(self.file, node.lineno, node.col_offset),
            "raw": snippet(node),
            "args": [self._argument(arg) for arg in node.args],
            "kwargs": {
                (keyword.arg if keyword.arg is not None else STARRED_KWARG_KEY): self._argument(
                    keyword.value
                )
                for keyword in node.keywords
            },
            "parent_name": self._parents[-1] if self._parents else None,
            "node": node,
        }

        bindings, dynamic = self._target_bindings(node.func)
        if bindings:
            emitted = [
                RawSymbolUsage(b.qualified_name, confidence=b.confidence, **common)
                for b in bindings
            ]
        elif dynamic:
            emitted = [RawSymbolUsage(None, confidence=CONFIDENCE_DYNAMIC, **common)]
        else:
            emitted = []

        self.usages.extend(emitted)
        return emitted

    def _argument(self, node: ast.AST) -> ArgValue:
        raw = snippet(node)
        if isinstance(node, ast.Call):
            return ArgValue(ArgKind.CALL, raw, resolved_name=self._best_name(node.func))
        if isinstance(node, ast.Attribute):
            return ArgValue(ArgKind.ATTRIBUTE, raw, resolved_name=self._best_name(node))
        if isinstance(node, ast.Name):
            return ArgValue(ArgKind.NAME, raw, resolved_name=self._best_name(node))
        try:
            return ArgValue(ArgKind.LITERAL, raw, value=ast.literal_eval(node))
        except _LITERAL_FAILURES:
            return ArgValue(ArgKind.UNRESOLVED, raw)

    def _best_name(self, node: ast.AST) -> str | None:
        bindings = self.table.resolve(dotted_parts(node))
        if not bindings:
            return None
        return max(bindings, key=lambda b: (b.confidence, b.qualified_name or "")).qualified_name


def analyze_source(
    source: str | bytes,
    file: str = "<source>",
    package: str | None = None,
    is_crypto_name: Callable[[str], bool] | None = None,
) -> list[RawSymbolUsage]:
    try:
        tree = ast.parse(source)
    except _PARSE_FAILURES as exc:
        logger.warning("cryptolens: skipping %s: %s", file, exc)
        return []
    analyzer = PythonAstAnalyzer(
        SymbolTable(package=package, is_crypto_name=is_crypto_name), file
    )
    analyzer.visit(tree)
    return analyzer.usages


def analyze_file(
    path: str | Path,
    root: str | Path,
    is_crypto_name: Callable[[str], bool] | None = None,
) -> list[RawSymbolUsage]:
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        logger.warning("cryptolens: cannot read %s: %s", path, exc)
        return []
    try:
        relative = path.resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        relative = path.as_posix()
    return analyze_source(data, relative, package_from_path(path, root), is_crypto_name)
