from pathlib import Path

from cryptolens.discovery.artifact_files import discover_artifact_files
from cryptolens.discovery.source_files import discover_source_files


def _touch(path: Path, content: bytes = b""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
def test_discovers_python_files(tmp_path):
    _touch(tmp_path / "src" / "main.py")
    _touch(tmp_path / "src" / "utils.py")
    _touch(tmp_path / "README.md")

    found = discover_source_files(tmp_path)
    names = {p.name for p in found}
    assert names == {"main.py", "utils.py"}
def test_ignores_default_dirs(tmp_path):
    _touch(tmp_path / "src" / "main.py")
    _touch(tmp_path / ".venv" / "lib" / "thing.py")
    _touch(tmp_path / "build" / "generated.py")
    found = discover_source_files(tmp_path)
    names = {p.name for p in found}
    assert names == {"main.py"}


def test_extra_ignore_flag(tmp_path):
    _touch(tmp_path / "vendor" / "thirdparty.py")
    _touch(tmp_path / "src" / "main.py")

    found = discover_source_files(tmp_path, extra_ignore=["vendor"])
    names = {p.name for p in found}
    assert names == {"main.py"}
    
def test_discovers_cert_by_extension(tmp_path):
    _touch(tmp_path / "certs" / "server.pem", b"-----BEGIN CERTIFICATE-----\n...")
    found = discover_artifact_files(tmp_path)
    assert len(found) == 1
    assert found[0].name == "server.pem"


def test_discovers_misnamed_pem_via_sniff(tmp_path):
    # no recognized extension, but PEM content
    _touch(tmp_path / "weird_file.txt.bak", b"-----BEGIN PRIVATE KEY-----\nMIIExyz\n")
    found = discover_artifact_files(tmp_path)
    assert len(found) == 1


def test_does_not_flag_normal_python_file_as_artifact(tmp_path):
    _touch(tmp_path / "main.py", b"print('hello')")
    found = discover_artifact_files(tmp_path)
    assert found == []