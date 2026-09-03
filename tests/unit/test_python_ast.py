"""Tests for the AST analyzer.

The analyzer's job is to hand detectors everything they need without them ever touching
the tree again: the qualified name, the arguments (including nested calls resolved through
the symbol table), the location, and a confidence.
"""

import ast
import textwrap

import pytest

from cryptolens.analyzers.python_ast import (
    BUILTINS_OF_INTEREST,
    CONFIDENCE_DYNAMIC,
    MAX_RAW_LENGTH,
    STARRED_KWARG_KEY,
    ArgKind,
    RawSymbolUsage,
    analyze_file,
    analyze_source,
    snippet,
)
from cryptolens.analyzers.symbol_table import CONFIDENCE_MULTIPLE, CONFIDENCE_WILDCARD


def usages(code: str, **kwargs) -> list[RawSymbolUsage]:
    return analyze_source(textwrap.dedent(code), **kwargs)


def one(code: str, name: str) -> RawSymbolUsage:
    matches = [u for u in usages(code) if u.resolved_name == name]
    assert len(matches) == 1, f"expected one {name}, got {[u.resolved_name for u in usages(code)]}"
    return matches[0]


# ------------------------------------------------------------------- argument capture


def test_keyword_literal_is_captured_as_a_value():
    """rsa.generate_private_key(key_size=2048) -- the key size is the whole point."""
    usage = one(
        """
        from cryptography.hazmat.primitives.asymmetric import rsa
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        """,
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
    )
    assert usage.kwargs["key_size"].kind is ArgKind.LITERAL
    assert usage.kwargs["key_size"].value == 2048
    assert usage.kwargs["public_exponent"].value == 65537


def test_nested_call_argument_is_resolved_through_the_symbol_table():
    """ec.generate_private_key(ec.SECP256R1()) -- the curve is a nested call."""
    usage = one(
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        ec.generate_private_key(ec.SECP256R1())
        """,
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
    )
    curve = usage.args[0]
    assert curve.kind is ArgKind.CALL
    assert curve.resolved_name == "cryptography.hazmat.primitives.asymmetric.ec.SECP256R1"


def test_cipher_yields_both_algorithm_and_mode_without_a_second_pass():
    """The motivating case: Cipher(algorithms.AES(key), modes.GCM(iv))."""
    usage = one(
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        Cipher(algorithms.AES(key), modes.GCM(iv))
        """,
        "cryptography.hazmat.primitives.ciphers.Cipher",
    )
    assert [a.resolved_name for a in usage.args] == [
        "cryptography.hazmat.primitives.ciphers.algorithms.AES",
        "cryptography.hazmat.primitives.ciphers.modes.GCM",
    ]


def test_aliased_argument_resolves_to_its_qualified_name():
    usage = one(
        """
        from cryptography.hazmat.primitives.asymmetric import ec as elliptic
        elliptic.generate_private_key(elliptic.SECP384R1())
        """,
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
    )
    assert usage.args[0].resolved_name.endswith("ec.SECP384R1")


@pytest.mark.parametrize(
    ("expression", "expected"),
    [("2048", 2048), ("'sha256'", "sha256"), ("b'iv'", b"iv"), ("-1", -1), ("[1, 2]", [1, 2]),
     ("True", True), ("None", None)],
)
def test_literal_arguments_of_every_shape(expression, expected):
    usage = one(f"import hashlib\nhashlib.new({expression})\n", "hashlib.new")
    assert usage.args[0].kind is ArgKind.LITERAL
    assert usage.args[0].value == expected


def test_plain_variable_argument_is_a_name_with_no_resolution():
    usage = one("import hashlib\nhashlib.sha256(payload)\n", "hashlib.sha256")
    assert usage.args[0].kind is ArgKind.NAME
    assert usage.args[0].resolved_name is None
    assert usage.args[0].raw == "payload"


def test_attribute_argument_is_resolved():
    usage = one(
        """
        import hashlib
        from cryptography.hazmat.primitives import hashes
        hashlib.new(hashes.SHA256)
        """,
        "hashlib.new",
    )
    assert usage.args[0].kind is ArgKind.ATTRIBUTE
    assert usage.args[0].resolved_name == "cryptography.hazmat.primitives.hashes.SHA256"


def test_star_args_and_double_star_kwargs_are_recorded_not_dropped():
    usage = one(
        """
        from cryptography.hazmat.primitives.ciphers import Cipher
        Cipher(*parts, **config)
        """,
        "cryptography.hazmat.primitives.ciphers.Cipher",
    )
    assert usage.args[0].kind is ArgKind.UNRESOLVED
    assert usage.args[0].raw == "*parts"
    assert usage.kwargs[STARRED_KWARG_KEY].raw == "config"


# ------------------------------------------------------------------------- nesting


def test_nested_calls_are_also_reported_with_their_parent():
    found = usages(
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        Cipher(algorithms.AES(key), modes.GCM(iv))
        """
    )
    by_name = {u.resolved_name.rsplit(".", 1)[-1]: u for u in found}
    assert set(by_name) == {"Cipher", "AES", "GCM"}
    assert by_name["Cipher"].parent_name is None
    assert by_name["AES"].parent_name.endswith("ciphers.Cipher")
    assert by_name["GCM"].parent_name.endswith("ciphers.Cipher")


# ------------------------------------------------------------------ confidence & multiplicity


def test_one_usage_per_binding_when_a_name_is_ambiguous():
    found = usages(
        """
        from hashlib import sha256, md5
        algo = sha256
        algo = md5
        algo(data)
        """
    )
    calls = [u for u in found if u.raw == "algo(data)"]
    assert sorted(u.resolved_name for u in calls) == ["hashlib.md5", "hashlib.sha256"]
    assert all(u.confidence == CONFIDENCE_MULTIPLE for u in calls)


def test_confidence_is_inherited_from_the_symbol_table():
    usage = one("from hashlib import *\nsha256(data)\n", "hashlib.sha256")
    assert usage.confidence == CONFIDENCE_WILDCARD


# ---------------------------------------------------------------- dynamic and unresolved


def test_dynamically_dispatched_call_is_reported_at_low_confidence():
    found = usages(
        """
        import importlib
        mod = importlib.import_module(name)
        getattr(mod, chosen)(data)
        """
    )
    dynamic = [u for u in found if u.is_dynamic]
    assert len(dynamic) == 1
    assert dynamic[0].raw == "getattr(mod, chosen)(data)"
    assert dynamic[0].confidence == CONFIDENCE_DYNAMIC


def test_dynamic_import_itself_still_resolves_normally():
    usage = one(
        "import importlib\nimportlib.import_module(name)\n", "importlib.import_module"
    )
    assert usage.confidence == 1.0


@pytest.mark.parametrize("builtin", sorted(BUILTINS_OF_INTEREST))
def test_security_relevant_builtins_are_reported_without_an_import(builtin):
    found = usages(f"{builtin}(payload)\n")
    assert [u.resolved_name for u in found] == [builtin]


def test_ordinary_unresolvable_calls_are_skipped():
    """Otherwise every print() and local helper in the codebase becomes a usage."""
    assert usages("print(x)\nhelper(y)\nself.method(z)\n") == []


# ------------------------------------------------------------------------- location


def test_location_uses_the_line_of_the_call_node():
    found = usages(
        """
        import hashlib

        hashlib.sha256(
            data,
        )
        """
    )
    assert found[0].location.line == 4
    assert found[0].location.column == 0
    assert str(found[0].location) == "<source>:4"


def test_multiline_evidence_is_collapsed_to_one_line():
    found = usages("import hashlib\nhashlib.sha256(\n    data,\n)\n")
    assert found[0].raw == "hashlib.sha256(data)"


def test_long_evidence_is_truncated():
    long_call = "import hashlib\nhashlib.sha256(" + ", ".join(f"a{i}" for i in range(80)) + ")\n"
    found = usages(long_call)
    assert len(found[0].raw) == MAX_RAW_LENGTH
    assert found[0].raw.endswith("...")


def test_snippet_handles_a_node_it_cannot_unparse():
    assert snippet(ast.Name()) == "<unparseable>"


# ------------------------------------------------------------------------ file entry point


def test_analyze_file_uses_paths_relative_to_the_scan_root(tmp_path):
    module = tmp_path / "pkg" / "sub" / "crypto.py"
    module.parent.mkdir(parents=True)
    module.write_text("import hashlib\nhashlib.sha256(data)\n")

    found = analyze_file(module, tmp_path)
    assert found[0].location.file == "pkg/sub/crypto.py"


def test_analyze_file_derives_the_package_so_relative_imports_resolve(tmp_path):
    module = tmp_path / "pkg" / "sub" / "crypto.py"
    module.parent.mkdir(parents=True)
    module.write_text("from .helpers import sha256\nsha256(data)\n")

    found = analyze_file(module, tmp_path)
    assert found[0].resolved_name == "pkg.sub.helpers.sha256"


def test_analyze_file_honours_a_pep263_encoding_declaration(tmp_path):
    module = tmp_path / "latin.py"
    module.write_bytes("# -*- coding: latin-1 -*-\nimport hashlib\nhashlib.sha256(caf\xe9)\n".encode("latin-1"))
    assert [u.resolved_name for u in analyze_file(module, tmp_path)] == ["hashlib.sha256"]


# ----------------------------------------------------------------------- never crash


@pytest.mark.parametrize(
    "content",
    ["def broken(:\n", "", "\x00\x01\x02binary", "if True:\nbad indent\n"],
    ids=["syntax-error", "empty", "binary", "indentation-error"],
)
def test_bad_files_yield_no_usages_instead_of_raising(tmp_path, content):
    module = tmp_path / "bad.py"
    module.write_bytes(content.encode("utf-8", errors="surrogateescape"))
    assert analyze_file(module, tmp_path) == []


def test_missing_file_yields_no_usages(tmp_path):
    assert analyze_file(tmp_path / "nope.py", tmp_path) == []


def test_file_outside_the_scan_root_still_analyses(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("import hashlib\nhashlib.md5(x)\n")
    found = analyze_file(outside, tmp_path / "root")
    assert [u.resolved_name for u in found] == ["hashlib.md5"]


def test_deeply_nested_expression_does_not_raise(tmp_path):
    module = tmp_path / "deep.py"
    module.write_text("import hashlib\nhashlib.sha256(" + "(" * 60 + "x" + ")" * 60 + ")\n")
    assert analyze_file(module, tmp_path) is not None


# ------------------------------------------------------- methods on constructed objects


def test_method_on_a_constructed_object_keeps_its_arguments():
    """Without this, RSA signing loses its padding and hash entirely."""
    usage = one(
        """
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes
        key = rsa.generate_private_key(key_size=2048)
        key.sign(data, padding.PSS(salt_length=32), hashes.SHA256())
        """,
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key.sign",
    )
    assert [a.resolved_name for a in usage.args[1:]] == [
        "cryptography.hazmat.primitives.asymmetric.padding.PSS",
        "cryptography.hazmat.primitives.hashes.SHA256",
    ]


def test_chained_call_resolves_through_its_receiver():
    """hashlib.sha256(x).hexdigest() must behave like the two-statement form."""
    found = usages("import hashlib\nhashlib.sha256(payload).hexdigest()\n")
    assert sorted(u.resolved_name for u in found) == [
        "hashlib.sha256",
        "hashlib.sha256.hexdigest",
    ]
    assert all(not u.is_dynamic for u in found)


def test_chains_of_more_than_one_link_resolve():
    found = usages(
        """
        from cryptography.hazmat.primitives.ciphers import Cipher
        Cipher(alg, mode).encryptor().update(data)
        """
    )
    names = {u.resolved_name for u in found}
    assert "cryptography.hazmat.primitives.ciphers.Cipher.encryptor.update" in names


@pytest.mark.parametrize(
    "code",
    ["getattr(mod, chosen)(data)", "funcs[i](data)", "(lambda: f)()(data)"],
    ids=["getattr", "subscript", "lambda"],
)
def test_genuinely_dynamic_dispatch_is_still_reported_as_dynamic(code):
    assert any(u.is_dynamic for u in usages(code + "\n"))
