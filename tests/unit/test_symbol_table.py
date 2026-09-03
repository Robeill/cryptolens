"""Symbol table tests: one per row of the edge-case policy table in PLAN.md Step 3.

Each test parses an inline code string, walks it, and asserts what the call sites at the
end resolve to. Nothing touches the filesystem.
"""

import ast
import textwrap

import pytest

from cryptolens.analyzers.symbol_table import (
    CONFIDENCE_CONDITIONAL,
    CONFIDENCE_DIRECT,
    CONFIDENCE_MULTIPLE,
    CONFIDENCE_WILDCARD,
    Binding,
    BindingKind,
    SymbolTable,
    SymbolTableWalker,
    dotted_parts,
    package_from_path,
)


class CallCollector(SymbolTableWalker):
    """Records every call site and what the symbol table made of its target."""

    def __init__(self, table):
        super().__init__(table)
        self.calls: list[tuple[str, list[Binding]]] = []

    def handle_call(self, node, bindings):
        self.calls.append((ast.unparse(node.func), bindings))


def walk(code: str, package: str | None = None) -> CallCollector:
    table = SymbolTable(package=package)
    collector = CallCollector(table)
    collector.visit(ast.parse(textwrap.dedent(code)))
    return collector


def names_for(collector: CallCollector, source: str) -> list[str]:
    """Qualified names resolved for the call whose source text is `source`."""
    for text, bindings in collector.calls:
        if text == source:
            return sorted(b.qualified_name for b in bindings)
    raise AssertionError(f"no call site {source!r} in {[c[0] for c in collector.calls]}")


def confidence_for(collector: CallCollector, source: str) -> float:
    for text, bindings in collector.calls:
        if text == source:
            assert bindings, f"{source!r} resolved to nothing"
            return max(b.confidence for b in bindings)
    raise AssertionError(f"no call site {source!r}")


# ------------------------------------------------------------------ the five spellings


@pytest.mark.parametrize(
    ("code", "call"),
    [
        ("import hashlib", "hashlib.sha256"),
        ("import hashlib as hl", "hl.sha256"),
        ("from hashlib import sha256", "sha256"),
        ("from hashlib import sha256 as h", "h"),
        ("import hashlib\nalgo = hashlib.sha256", "algo"),
    ],
    ids=["plain", "aliased-module", "from-import", "aliased-member", "variable"],
)
def test_every_spelling_of_the_same_call_resolves_identically(code, call):
    """The point of the module: five different spellings, one qualified name."""
    collector = walk(f"{code}\n{call}(data)\n")
    assert names_for(collector, call) == ["hashlib.sha256"]


# ------------------------------------------------------- row 1: `import a.b.c` binds `a`


def test_dotted_import_binds_only_the_top_package_but_resolves_the_chain():
    collector = walk("import a.b.c\na.b.c.f(x)\n")
    assert names_for(collector, "a.b.c.f") == ["a.b.c.f"]


def test_dotted_import_with_alias_binds_the_full_path():
    collector = walk("import a.b.c as abc\nabc.f(x)\n")
    assert names_for(collector, "abc.f") == ["a.b.c.f"]


# --------------------------------------------------------- row 2: imports inside functions


def test_import_inside_a_function_is_scoped_to_that_function():
    collector = walk(
        """
        def inner():
            import hashlib
            hashlib.sha256(a)

        def outer():
            hashlib.sha256(b)
        """
    )
    inner, outer = collector.calls
    assert [b.qualified_name for b in inner[1]] == ["hashlib.sha256"]
    assert outer[1] == []


# ------------------------------------------------------------------- row 3: wildcard import


def test_wildcard_import_resolves_known_crypto_names_at_low_confidence():
    collector = walk("from hashlib import *\nsha256(data)\n")
    assert names_for(collector, "sha256") == ["hashlib.sha256"]
    assert confidence_for(collector, "sha256") == CONFIDENCE_WILDCARD


def test_wildcard_import_ignores_names_that_are_not_crypto_exports():
    collector = walk("from hashlib import *\nhelper(data)\n")
    assert names_for(collector, "helper") == []


# ----------------------------------------------------------------- row 4: relative imports


def test_relative_import_resolves_against_the_package_path():
    collector = walk("from .crypto import h\nh(data)\n", package="pkg.sub")
    assert names_for(collector, "h") == ["pkg.sub.crypto.h"]


def test_parent_relative_import_climbs_one_level():
    collector = walk("from ..crypto import h\nh(data)\n", package="pkg.sub")
    assert names_for(collector, "h") == ["pkg.crypto.h"]


def test_relative_import_that_climbs_past_the_root_is_skipped_not_crashed():
    collector = walk("from ....crypto import h\nh(data)\n", package="pkg")
    assert names_for(collector, "h") == []


def test_relative_import_without_a_known_package_is_skipped():
    collector = walk("from .crypto import h\nh(data)\n", package=None)
    assert names_for(collector, "h") == []


# ------------------------------------------------------------- row 5: conditional imports


def test_conditional_import_records_both_branches_at_reduced_confidence():
    collector = walk(
        """
        try:
            from fast_crypto import sha256
        except ImportError:
            from hashlib import sha256
        sha256(data)
        """
    )
    assert names_for(collector, "sha256") == ["fast_crypto.sha256", "hashlib.sha256"]
    assert confidence_for(collector, "sha256") == CONFIDENCE_CONDITIONAL


def test_try_that_is_not_an_import_guard_keeps_full_confidence():
    collector = walk(
        """
        try:
            import hashlib
        except ValueError:
            pass
        hashlib.sha256(data)
        """
    )
    assert confidence_for(collector, "hashlib.sha256") == CONFIDENCE_DIRECT


# --------------------------------------------------------------- row 6: local shadowing


def test_a_local_variable_shadows_an_import_inside_its_scope():
    collector = walk(
        """
        import hashlib

        def f():
            hashlib = load_config()
            hashlib.sha256(a)
        """
    )
    assert names_for(collector, "hashlib.sha256") == []


def test_the_import_is_restored_after_the_shadowing_scope_exits():
    collector = walk(
        """
        import hashlib

        def f():
            hashlib = load_config()
            hashlib.sha256(a)

        hashlib.sha256(b)
        """
    )
    shadowed = collector.calls[1][1]
    restored = collector.calls[2][1]
    assert shadowed == []
    assert [b.qualified_name for b in restored] == ["hashlib.sha256"]


# ------------------------------------------------------------------- row 7: re-assignment


def test_reassignment_keeps_every_binding_rather_than_last_write_wins():
    """A scanner that misses is worse than one that over-reports at low confidence."""
    collector = walk(
        """
        from hashlib import sha256, md5
        algo = sha256
        algo = md5
        algo(data)
        """
    )
    assert names_for(collector, "algo") == ["hashlib.md5", "hashlib.sha256"]
    assert confidence_for(collector, "algo") == CONFIDENCE_MULTIPLE


def test_a_single_binding_keeps_full_confidence():
    collector = walk("from hashlib import sha256\nalgo = sha256\nalgo(data)\n")
    assert confidence_for(collector, "algo") == CONFIDENCE_DIRECT


# ---------------------------------------------------------------- row 8: self.attribute


def test_self_attribute_resolves_within_the_same_class():
    collector = walk(
        """
        import hashlib

        class Hasher:
            def __init__(self):
                self.algo = hashlib.sha256

            def run(self, data):
                return self.algo(data)
        """
    )
    assert names_for(collector, "self.algo") == ["hashlib.sha256"]


def test_self_attribute_does_not_leak_across_classes():
    collector = walk(
        """
        import hashlib

        class Hasher:
            def __init__(self):
                self.algo = hashlib.sha256

        class Other:
            def run(self, data):
                return self.algo(data)
        """
    )
    assert names_for(collector, "self.algo") == []


# -------------------------------------------------------------------- resilience & helpers


def test_unresolvable_dynamic_call_yields_no_bindings_and_does_not_raise():
    collector = walk(
        """
        import importlib
        mod = importlib.import_module(name)
        getattr(mod, chosen)(data)
        """
    )
    assert collector.calls
    assert names_for(collector, "getattr(mod, chosen)") == []


def test_nested_call_targets_are_still_visited():
    collector = walk("import hashlib\nouter(hashlib.sha256(data))\n")
    assert names_for(collector, "hashlib.sha256") == ["hashlib.sha256"]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("a", ["a"]),
        ("a.b.c", ["a", "b", "c"]),
        ("a().b", None),
        ("'literal'.upper", None),
    ],
)
def test_dotted_parts_handles_non_name_chains(source, expected):
    assert dotted_parts(ast.parse(source, mode="eval").body) == expected


def test_package_from_path():
    assert package_from_path("/repo/pkg/sub/mod.py", "/repo") == "pkg.sub"
    assert package_from_path("/repo/mod.py", "/repo") == ""
    assert package_from_path("/elsewhere/mod.py", "/repo") is None


def test_binding_resolvability():
    assert Binding("hashlib.sha256").is_resolvable
    assert not Binding(None, BindingKind.OPAQUE).is_resolvable
    assert not Binding("<unresolved-relative>", BindingKind.UNRESOLVED_RELATIVE).is_resolvable


def test_relative_import_climbing_to_the_scan_root_resolves_to_a_top_level_module():
    """`from ..crypto import h` inside package `pkg` means <root>/crypto, which is in scope."""
    collector = walk("from ..crypto import h\nh(data)\n", package="pkg")
    assert names_for(collector, "h") == ["crypto.h"]


def test_bare_except_around_an_import_counts_as_conditional():
    collector = walk(
        """
        try:
            from fast_crypto import sha256
        except:
            from hashlib import sha256
        sha256(data)
        """
    )
    assert confidence_for(collector, "sha256") == CONFIDENCE_CONDITIONAL


def test_try_without_imports_does_not_lower_confidence():
    collector = walk(
        """
        import hashlib
        try:
            risky()
        except ImportError:
            pass
        hashlib.sha256(data)
        """
    )
    assert confidence_for(collector, "hashlib.sha256") == CONFIDENCE_DIRECT


def test_self_attribute_assigned_something_unresolvable_shadows_rather_than_resolves():
    collector = walk(
        """
        import hashlib

        class Hasher:
            def __init__(self, cfg):
                self.algo = cfg.pick()

            def run(self, data):
                return self.algo(data)
        """
    )
    assert names_for(collector, "self.algo") == []


def test_class_attribute_binding_outside_a_class_is_ignored():
    table = SymbolTable()
    table.bind_class_attribute("algo", Binding("hashlib.sha256"))
    assert table.resolve(["self", "algo"]) == []


def test_resolve_node_accepts_an_ast_node_directly():
    table = SymbolTable()
    SymbolTableWalker(table).visit(ast.parse("import hashlib"))
    node = ast.parse("hashlib.sha256", mode="eval").body
    assert [b.qualified_name for b in table.resolve_node(node)] == ["hashlib.sha256"]


def test_build_symbol_table_returns_a_populated_table():
    from cryptolens.analyzers.symbol_table import build_symbol_table

    table = build_symbol_table(ast.parse("import hashlib as hl\nfrom os import *\n"))
    assert [b.qualified_name for b in table.resolve(["hl", "sha256"])] == ["hashlib.sha256"]
    assert table.wildcard_modules == ["os"]


# ------------------------------------------------------- instances of constructed objects


def test_assignment_from_a_resolvable_call_binds_the_constructor():
    """The canonical pyca/cryptography signing idiom: key = generate(); key.sign(...)."""
    collector = walk(
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(key_size=2048)
        key.sign(data)
        """
    )
    assert names_for(collector, "key.sign") == [
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key.sign"
    ]


def test_annotated_assignment_binds_the_same_way():
    collector = walk(
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        key: object = rsa.generate_private_key(key_size=2048)
        key.sign(data)
        """
    )
    assert names_for(collector, "key.sign")[0].endswith("generate_private_key.sign")


def test_annotation_without_a_value_binds_nothing():
    collector = walk("import hashlib\nkey: object\nhashlib.sha256(data)\n")
    assert names_for(collector, "hashlib.sha256") == ["hashlib.sha256"]


def test_self_attribute_from_a_constructor_resolves_in_other_methods():
    collector = walk(
        """
        from cryptography.hazmat.primitives.asymmetric import rsa

        class Signer:
            def __init__(self):
                self.key = rsa.generate_private_key(key_size=2048)

            def run(self, data):
                return self.key.sign(data)
        """
    )
    assert names_for(collector, "self.key.sign")[0].endswith("generate_private_key.sign")


def test_assignment_from_an_unresolvable_call_is_still_opaque():
    """Shadowing must keep working: an unknown callee resolves to nothing, not a guess."""
    collector = walk(
        """
        import hashlib

        def f():
            hashlib = load_config()
            hashlib.sha256(a)
        """
    )
    assert names_for(collector, "hashlib.sha256") == []


def test_a_resolvable_call_still_shadows_the_name_it_is_assigned_to():
    collector = walk(
        """
        import hashlib
        import json

        def f():
            hashlib = json.loads(raw)
            hashlib.sha256(a)
        """
    )
    assert names_for(collector, "hashlib.sha256") == ["json.loads.sha256"]
