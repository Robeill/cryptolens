from __future__ import annotations

from collections.abc import Iterable

from cryptolens.analyzers.python_ast import ArgValue, RawSymbolUsage
from cryptolens.detectors.normalize import normalize_algorithm, normalize_composite
from cryptolens.detectors.rules import (
    CIPHER_ALGORITHMS,
    CIPHER_MODES,
    CURVES,
    RULES,
    UNSET,
    Rule,
)
from cryptolens.model import CryptoFinding, CryptoMode

RSA_STRENGTH = {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256}


class DetectorEngine:
    def __init__(self, rules: Iterable[Rule] = RULES) -> None:
        self.rules: dict[str, Rule] = {rule.match: rule for rule in rules}

    def detect(self, usages: Iterable[RawSymbolUsage]) -> list[CryptoFinding]:
        findings = []
        for usage in usages:
            finding = self.detect_one(usage)
            if finding is not None:
                findings.append(finding)
        return findings

    def detect_one(self, usage: RawSymbolUsage) -> CryptoFinding | None:
        if usage.resolved_name is None or self._consumed_by_parent(usage):
            return None
        rule = self.rules.get(usage.resolved_name)
        if rule is None or not rule.emits or not self._value_matches(rule, usage):
            return None
        return self._build(rule, usage)

    def _consumed_by_parent(self, usage: RawSymbolUsage) -> bool:
        parent = self.rules.get(usage.parent_name or "")
        return parent is not None and parent.consumes_args

    @staticmethod
    def _value_matches(rule: Rule, usage: RawSymbolUsage) -> bool:
        if rule.value_name is None and rule.value_equals is UNSET:
            return True
        if not usage.args:
            return False
        value = usage.args[0]
        if rule.value_name is not None:
            return value.resolved_name == rule.value_name
        return value.value == rule.value_equals

    def _build(self, rule: Rule, usage: RawSymbolUsage) -> CryptoFinding:
        algorithm = rule.algorithm
        primitive = rule.primitive
        purpose = rule.purpose
        mode = rule.mode
        strength = rule.classical_security_level
        parameter_set = rule.parameter_set
        curve = None
        key_size = rule.key_size

        named = self._literal(usage, rule.name_arg)
        if named is not None:
            algorithm = normalize_algorithm(str(named))

        if rule.algorithm_arg is not None:
            resolved = self._resolved(usage, rule.algorithm_arg)
            if resolved in CIPHER_ALGORITHMS:
                algorithm, primitive, strength = CIPHER_ALGORITHMS[resolved]

        if rule.mode_arg is not None:
            mode = CIPHER_MODES.get(self._resolved(usage, rule.mode_arg) or "", CryptoMode.UNKNOWN)

        if rule.curve_arg is not None:
            resolved = self._resolved(usage, rule.curve_arg)
            if resolved in CURVES:
                parameter_set, strength = CURVES[resolved]
                curve = parameter_set

        digest = self._digest(usage, rule)
        if digest is not None:
            algorithm = normalize_composite(rule.algorithm, digest)

        if key_size is None:
            key_size = self._key_size(usage, rule)
        if key_size is not None and rule.algorithm == "RSA":
            strength = RSA_STRENGTH.get(key_size, strength)

        return CryptoFinding(
            algorithm=normalize_algorithm(algorithm),
            location=usage.location,
            purpose=purpose,
            evidence=usage.raw,
            asset_type=rule.asset_type,
            primitive=primitive,
            mode=mode,
            padding=rule.padding,
            crypto_functions=list(rule.functions),
            parameter_set=parameter_set,
            curve=curve,
            key_size=key_size,
            status=rule.status,
            classical_security_level=strength,
            confidence=min(usage.confidence, rule.confidence or 1.0),
            detector=rule.detector or rule.match,
        )

    @staticmethod
    def _argument(usage: RawSymbolUsage, index: int | None) -> ArgValue | None:
        if index is None or index >= len(usage.args):
            return None
        return usage.args[index]

    def _resolved(self, usage: RawSymbolUsage, index: int | None) -> str | None:
        argument = self._argument(usage, index)
        return argument.resolved_name if argument else None

    def _literal(self, usage: RawSymbolUsage, index: int | None):
        argument = self._argument(usage, index)
        return argument.value if argument else None

    def _digest(self, usage: RawSymbolUsage, rule: Rule) -> str | None:
        if rule.digest_kwarg and rule.digest_kwarg in usage.kwargs:
            argument = usage.kwargs[rule.digest_kwarg]
        else:
            argument = self._argument(usage, rule.digest_arg)
        if argument is None:
            return None
        if argument.resolved_name:
            return argument.resolved_name.rsplit(".", 1)[-1]
        return str(argument.value) if argument.value is not None else None

    def _key_size(self, usage: RawSymbolUsage, rule: Rule) -> int | None:
        if rule.key_size_kwarg and rule.key_size_kwarg in usage.kwargs:
            value = usage.kwargs[rule.key_size_kwarg].value
            if isinstance(value, int):
                return value
        value = self._literal(usage, rule.key_size_arg)
        return value if isinstance(value, int) else None


def detect(usages: Iterable[RawSymbolUsage]) -> list[CryptoFinding]:
    return DetectorEngine().detect(usages)
