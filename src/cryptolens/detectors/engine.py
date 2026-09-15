from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from cryptolens.analyzers.python_ast import ArgValue, RawSymbolUsage
from cryptolens.detectors.normalize import normalize_algorithm, normalize_composite
from cryptolens.detectors.rules import (
    CIPHER_ALGORITHMS,
    CIPHER_MODES,
    CONFIDENCE_PURPOSE_AMBIGUOUS,
    CONFIDENCE_PURPOSE_FROM_USAGE,
    CURVES,
    HASH_STRENGTH,
    KEY_ACCESSORS,
    PURPOSE_BY_METHOD,
    RULES,
    UNSET,
    AlgorithmSpec,
    Rule,
)
from cryptolens.model import CryptoFinding, CryptoMode, CryptoPrimitive, CryptoPurpose

RSA_STRENGTH = {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256}


@dataclass(frozen=True)
class UsageContext:
    """Which methods were called on each resolvable receiver, per file.

    `ec.generate_private_key(...)` says nothing about what the key is for. `key.exchange(...)`
    on the result does, and the analyzer resolves that to `<keygen>.exchange`. This index is
    the join between the two.

    File-scoped rather than binding-scoped: two keys of the same kind in one file are
    indistinguishable here, so a purpose recovered this way is reported at reduced
    confidence.
    """

    methods: dict[tuple[str, str], set[str]] = field(default_factory=dict)

    @classmethod
    def from_usages(cls, usages: Iterable[RawSymbolUsage]) -> UsageContext:
        context = cls()
        for usage in usages:
            if usage.resolved_name is None or "." not in usage.resolved_name:
                continue
            base, _, method = usage.resolved_name.rpartition(".")
            context._record(usage.location.file, base, method)
            head, _, accessor = base.rpartition(".")
            if accessor in KEY_ACCESSORS and head:
                context._record(usage.location.file, head, method)
        return context

    def _record(self, file: str, base: str, method: str) -> None:
        self.methods.setdefault((file, base), set()).add(method)

    def methods_on(self, file: str, base: str) -> set[str]:
        return self.methods.get((file, base), set())


class DetectorEngine:
    def __init__(self, rules: Iterable[Rule] = RULES) -> None:
        self.rules: dict[str, list[Rule]] = {}
        for rule in rules:
            self.rules.setdefault(rule.match, []).append(rule)

    def detect(self, usages: Iterable[RawSymbolUsage]) -> list[CryptoFinding]:
        usages = list(usages)
        context = UsageContext.from_usages(usages)
        findings = []
        for usage in usages:
            findings.extend(self.detect_usage(usage, context))
        return findings

    def detect_usage(
        self, usage: RawSymbolUsage, context: UsageContext | None = None
    ) -> list[CryptoFinding]:
        if usage.resolved_name is None or self._consumed_by_parent(usage):
            return []
        findings = []
        for rule in self.rules.get(usage.resolved_name, ()):
            if not rule.emits or not self._value_matches(rule, usage):
                continue
            findings.extend(self._build_all(rule, usage, context))
        return findings

    def _consumed_by_parent(self, usage: RawSymbolUsage) -> bool:
        parents = self.rules.get(usage.parent_name or "", ())
        return any(parent.consumes_args for parent in parents)

    def _value_matches(self, rule: Rule, usage: RawSymbolUsage) -> bool:
        if rule.value_name is None and rule.value_equals is UNSET:
            return True
        if rule.value_kwarg is not None:
            argument = usage.kwargs.get(rule.value_kwarg)
        else:
            argument = usage.args[0] if usage.args else None
        if argument is None:
            return False
        if rule.value_name is not None:
            return argument.resolved_name == rule.value_name
        value = argument.value
        if rule.value_key is not None:
            if not isinstance(value, dict):
                return False
            value = value.get(rule.value_key, UNSET)
        if isinstance(rule.value_equals, bool):
            return value is rule.value_equals
        return value == rule.value_equals

    def _build_all(
        self, rule: Rule, usage: RawSymbolUsage, context: UsageContext | None = None
    ) -> list[CryptoFinding]:
        if rule.spec_table is None:
            return [self._build(rule, usage, context=context)]
        specs = [rule.spec_table[n] for n in self._named_values(usage, rule) if n in rule.spec_table]
        if not specs:
            return [self._build(rule, usage, context=context)]
        return [self._build(rule, usage, spec, context) for spec in specs]

    def _named_values(self, usage: RawSymbolUsage, rule: Rule) -> list[str]:
        argument = None
        if rule.name_kwarg and rule.name_kwarg in usage.kwargs:
            argument = usage.kwargs[rule.name_kwarg]
        elif rule.name_arg is not None:
            argument = self._argument(usage, rule.name_arg)
        if argument is None or argument.value is None:
            return []
        value = argument.value
        if isinstance(value, str):
            return [value]
        if isinstance(value, (list, tuple, set)):
            return [item for item in value if isinstance(item, str)]
        return []

    def _build(
        self,
        rule: Rule,
        usage: RawSymbolUsage,
        spec: AlgorithmSpec | None = None,
        context: UsageContext | None = None,
    ) -> CryptoFinding:
        algorithm = rule.algorithm
        primitive = rule.primitive
        purpose = rule.purpose
        mode = rule.mode
        strength = rule.classical_security_level
        parameter_set = rule.parameter_set
        curve = None
        key_size = rule.key_size

        functions = list(rule.functions)
        padding = rule.padding
        status = rule.status

        if spec is not None:
            algorithm = spec.algorithm
            primitive = spec.primitive
            purpose = spec.purpose
            padding = spec.padding
            status = spec.status
            parameter_set = spec.parameter_set
            curve = spec.curve
            strength = spec.classical_security_level
            functions = list(spec.functions) or functions
        elif rule.spec_table is None:
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
            if strength is None:
                strength = HASH_STRENGTH.get(normalize_algorithm(digest))

        if key_size is None:
            key_size = self._key_size(usage, rule)
        if key_size is not None and rule.algorithm == "RSA":
            strength = RSA_STRENGTH.get(key_size, strength)

        confidence = min(usage.confidence, rule.confidence or 1.0)
        if rule.resolve_purpose and purpose is CryptoPurpose.UNKNOWN:
            purpose, primitive, ceiling = self._purpose_from_usage(
                rule, usage, context, primitive
            )
            confidence = min(confidence, ceiling)

        return CryptoFinding(
            algorithm=normalize_algorithm(algorithm),
            location=usage.location,
            purpose=purpose,
            evidence=usage.raw,
            asset_type=rule.asset_type,
            primitive=primitive,
            mode=mode,
            padding=padding,
            crypto_functions=functions,
            parameter_set=parameter_set,
            curve=curve,
            key_size=key_size,
            status=status,
            classical_security_level=strength,
            confidence=confidence,
            detector=rule.detector or rule.match,
            extra=dict(rule.extra) if rule.extra else {},
        )

    def _purpose_from_usage(
        self,
        rule: Rule,
        usage: RawSymbolUsage,
        context: UsageContext | None,
        primitive: CryptoPrimitive,
    ) -> tuple[CryptoPurpose, CryptoPrimitive, float]:
        """Recover what an ambiguous call is for by looking at how its result is used.

        Two tiers. The receiving call is exact -- `key.sign(msg, padding.PKCS1v15(), ...)`
        settles that padding with no guesswork, so full confidence is kept. Falling back to
        every method seen on that receiver anywhere in the file is an approximation, so it is
        capped. Neither tier guesses: an unresolvable call stays `UNKNOWN`, at a confidence
        that says so.
        """
        exact = PURPOSE_BY_METHOD.get((usage.parent_name or "").rpartition(".")[2])
        if exact is not None:
            return exact[0], exact[1], 1.0

        if context is not None:
            candidates = {
                PURPOSE_BY_METHOD[method]
                for method in context.methods_on(usage.location.file, rule.match)
                if method in PURPOSE_BY_METHOD
            }
            if len(candidates) == 1:
                purpose, resolved = next(iter(candidates))
                return purpose, resolved, CONFIDENCE_PURPOSE_FROM_USAGE

        return CryptoPurpose.UNKNOWN, primitive, CONFIDENCE_PURPOSE_AMBIGUOUS

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
