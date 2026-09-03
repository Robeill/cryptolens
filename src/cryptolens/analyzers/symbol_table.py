from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

CONFIDENCE_DIRECT = 1.0
CONFIDENCE_CONDITIONAL = 0.6
CONFIDENCE_MULTIPLE = 0.5
CONFIDENCE_WILDCARD = 0.4

UNRESOLVED_RELATIVE = "<unresolved-relative>"

LIKELY_CRYPTO_EXPORTS = frozenset(
    {
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha3_224", "sha3_256", "sha3_384", "sha3_512", "shake_128", "shake_256",
        "blake2b", "blake2s", "new", "pbkdf2_hmac", "scrypt",
        "HMAC", "AES", "DES", "DES3", "ARC2", "ARC4", "ChaCha20", "Blowfish",
        "RSA", "DSA", "ECC", "PKCS1_OAEP", "PKCS1_v1_5", "PBKDF2",
        "Cipher", "Fernet", "encrypt", "decrypt", "sign", "verify",
        "generate_private_key", "derive_private_key", "load_pem_private_key",
        "token_bytes", "token_hex", "token_urlsafe", "urandom",
    }
)

IMPORT_ERROR_NAMES = ("ImportError", "ModuleNotFoundError")


class BindingKind(str, Enum):
    IMPORT = "import"
    CONDITIONAL_IMPORT = "conditional_import"
    ASSIGNMENT = "assignment"
    INSTANCE = "instance"
    CLASS_ATTRIBUTE = "class_attribute"
    WILDCARD = "wildcard"
    OPAQUE = "opaque"
    UNRESOLVED_RELATIVE = "unresolved_relative"


_UNRESOLVABLE = (BindingKind.OPAQUE, BindingKind.UNRESOLVED_RELATIVE)


@dataclass(frozen=True)
class Binding:
    qualified_name: str | None
    kind: BindingKind = BindingKind.IMPORT
    confidence: float = CONFIDENCE_DIRECT

    @property
    def is_resolvable(self) -> bool:
        return self.qualified_name is not None and self.kind not in _UNRESOLVABLE


def package_from_path(file: str | Path, root: str | Path) -> str | None:
    file = Path(file).resolve()
    root = Path(root).resolve()
    try:
        relative = file.relative_to(root)
    except ValueError:
        return None
    parts = relative.parts[:-1]
    return ".".join(parts) if parts else ""


def dotted_parts(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    parts.reverse()
    return parts


def _default_is_crypto_name(name: str) -> bool:
    return name in LIKELY_CRYPTO_EXPORTS


class SymbolTable:
    def __init__(
        self,
        package: str | None = None,
        is_crypto_name: Callable[[str], bool] | None = None,
    ) -> None:
        self.package = package
        self.wildcard_modules: list[str] = []
        self._scopes: list[dict[str, list[Binding]]] = [{}]
        self._class_attributes: dict[str, dict[str, list[Binding]]] = {}
        self._class_stack: list[str] = []
        self._is_crypto_name = is_crypto_name or _default_is_crypto_name

    @property
    def current_class(self) -> str | None:
        return self._class_stack[-1] if self._class_stack else None

    def push_scope(self) -> None:
        self._scopes.append({})

    def pop_scope(self) -> None:
        if len(self._scopes) > 1:
            self._scopes.pop()

    def enter_class(self, name: str) -> None:
        self._class_stack.append(name)
        self._class_attributes.setdefault(name, {})
        self.push_scope()

    def exit_class(self) -> None:
        self.pop_scope()
        if self._class_stack:
            self._class_stack.pop()

    def bind(self, name: str, binding: Binding) -> None:
        self._scopes[-1].setdefault(name, []).append(binding)

    def bind_class_attribute(self, name: str, binding: Binding) -> None:
        if not self._class_stack:
            return
        attributes = self._class_attributes.setdefault(self._class_stack[-1], {})
        attributes.setdefault(name, []).append(binding)

    def lookup(self, name: str) -> list[Binding]:
        for scope in reversed(self._scopes):
            if name in scope:
                return scope[name]
        return []

    def resolve(self, parts: list[str] | None) -> list[Binding]:
        if not parts:
            return []
        if parts[0] == "self" and len(parts) > 1 and self.current_class:
            attributes = self._class_attributes.get(self.current_class, {})
            return self._extend(attributes.get(parts[1], []), parts[2:])
        bindings = self.lookup(parts[0])
        if not bindings:
            return self._resolve_through_wildcard(parts)
        return self._extend(bindings, parts[1:])

    def resolve_node(self, node: ast.AST) -> list[Binding]:
        return self.resolve(dotted_parts(node))

    def _extend(self, bindings: list[Binding], rest: list[str]) -> list[Binding]:
        usable = [b for b in bindings if b.is_resolvable]
        if not usable:
            return []
        cap = None
        if len(usable) > 1 and not all(b.kind is BindingKind.CONDITIONAL_IMPORT for b in usable):
            cap = CONFIDENCE_MULTIPLE
        suffix = "." + ".".join(rest) if rest else ""
        return [
            Binding(
                f"{b.qualified_name}{suffix}",
                b.kind,
                b.confidence if cap is None else min(b.confidence, cap),
            )
            for b in usable
        ]

    def _resolve_through_wildcard(self, parts: list[str]) -> list[Binding]:
        if not self.wildcard_modules or not self._is_crypto_name(parts[0]):
            return []
        suffix = "." + ".".join(parts[1:]) if len(parts) > 1 else ""
        return [
            Binding(
                f"{module}.{parts[0]}{suffix}",
                BindingKind.WILDCARD,
                CONFIDENCE_WILDCARD,
            )
            for module in self.wildcard_modules
        ]


class SymbolTableWalker(ast.NodeVisitor):
    def __init__(self, table: SymbolTable) -> None:
        self.table = table
        self._import_kind = BindingKind.IMPORT

    def handle_call(self, node: ast.Call, bindings: list[Binding]) -> None:
        pass

    def _import_confidence(self) -> float:
        if self._import_kind is BindingKind.CONDITIONAL_IMPORT:
            return CONFIDENCE_CONDITIONAL
        return CONFIDENCE_DIRECT

    def visit_Import(self, node: ast.Import) -> None:
        confidence = self._import_confidence()
        for alias in node.names:
            if alias.asname:
                self.table.bind(
                    alias.asname, Binding(alias.name, self._import_kind, confidence)
                )
            else:
                top = alias.name.split(".")[0]
                self.table.bind(top, Binding(top, self._import_kind, confidence))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = self._absolute_module(node)
        confidence = self._import_confidence()
        if module is None:
            for alias in node.names:
                self.table.bind(
                    alias.asname or alias.name,
                    Binding(UNRESOLVED_RELATIVE, BindingKind.UNRESOLVED_RELATIVE, 0.0),
                )
            return
        for alias in node.names:
            if alias.name == "*":
                if module not in self.table.wildcard_modules:
                    self.table.wildcard_modules.append(module)
                continue
            self.table.bind(
                alias.asname or alias.name,
                Binding(f"{module}.{alias.name}", self._import_kind, confidence),
            )

    def _absolute_module(self, node: ast.ImportFrom) -> str | None:
        if not node.level:
            return node.module
        if self.table.package is None:
            return None
        parts = [p for p in self.table.package.split(".") if p]
        keep = len(parts) - (node.level - 1)
        if keep < 0:
            return None
        base = ".".join(parts[:keep])
        if not base:
            return node.module
        return f"{base}.{node.module}" if node.module else base

    def visit_Try(self, node: ast.Try) -> None:
        previous = self._import_kind
        if self._is_conditional_import(node):
            self._import_kind = BindingKind.CONDITIONAL_IMPORT
        self.generic_visit(node)
        self._import_kind = previous

    @staticmethod
    def _is_conditional_import(node: ast.Try) -> bool:
        has_import = any(isinstance(n, (ast.Import, ast.ImportFrom)) for n in node.body)
        if not has_import:
            return False
        for handler in node.handlers:
            if handler.type is None:
                return True
            for name in ast.walk(handler.type):
                if isinstance(name, ast.Name) and name.id in IMPORT_ERROR_NAMES:
                    return True
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.table.push_scope()
        self.generic_visit(node)
        self.table.pop_scope()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.table.enter_class(node.name)
        self.generic_visit(node)
        self.table.exit_class()

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        bindings = self._value_bindings(node.value)
        for target in node.targets:
            self._bind_target(target, bindings)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is None:
            return
        self.visit(node.value)
        self._bind_target(node.target, self._value_bindings(node.value))

    def _value_bindings(self, value: ast.AST) -> list[Binding]:
        if isinstance(value, ast.Call):
            return [
                Binding(b.qualified_name, BindingKind.INSTANCE, b.confidence)
                for b in self.table.resolve(dotted_parts(value.func))
            ]
        return self.table.resolve(dotted_parts(value))

    @staticmethod
    def _carried_kind(binding: Binding, default: BindingKind) -> BindingKind:
        return binding.kind if binding.kind is BindingKind.INSTANCE else default

    def _bind_target(self, target: ast.AST, bindings: list[Binding]) -> None:
        if isinstance(target, ast.Name):
            if bindings:
                for binding in bindings:
                    self.table.bind(
                        target.id,
                        Binding(
                            binding.qualified_name,
                            self._carried_kind(binding, BindingKind.ASSIGNMENT),
                            binding.confidence,
                        ),
                    )
            else:
                self.table.bind(target.id, Binding(None, BindingKind.OPAQUE, 0.0))
            return
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"
        ):
            if bindings:
                for binding in bindings:
                    self.table.bind_class_attribute(
                        target.attr,
                        Binding(
                            binding.qualified_name,
                            self._carried_kind(binding, BindingKind.CLASS_ATTRIBUTE),
                            binding.confidence,
                        ),
                    )
            else:
                self.table.bind_class_attribute(
                    target.attr, Binding(None, BindingKind.OPAQUE, 0.0)
                )

    def visit_Call(self, node: ast.Call) -> None:
        self.handle_call(node, self.table.resolve(dotted_parts(node.func)))
        self.generic_visit(node)


def build_symbol_table(
    tree: ast.AST,
    package: str | None = None,
    is_crypto_name: Callable[[str], bool] | None = None,
) -> SymbolTable:
    table = SymbolTable(package=package, is_crypto_name=is_crypto_name)
    SymbolTableWalker(table).visit(tree)
    return table
