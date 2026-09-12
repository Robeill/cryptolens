from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CertificateProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoMode,
    CryptoPadding,
    CryptoPrimitive,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesType,
    RelatedCryptoMaterialProperties,
    RelatedCryptoMaterialType,
)
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from cryptolens.cbom.aggregate import CryptoAsset
from cryptolens.model import AssetType

logger = logging.getLogger(__name__)

TOOL_VENDOR = "cryptolens"
TOOL_NAME = "cryptolens"
DEFAULT_SCHEMA_VERSION = SchemaVersion.V1_6

PROTOCOL_TYPES: dict[str, ProtocolPropertiesType] = {
    "TLS": ProtocolPropertiesType.TLS,
    "DTLS": ProtocolPropertiesType.DTLS,
    "SSH": ProtocolPropertiesType.SSH,
    "IPSEC": ProtocolPropertiesType.IPSEC,
    "IKE": ProtocolPropertiesType.IKE,
    "QUIC": ProtocolPropertiesType.QUIC,
    "WPA": ProtocolPropertiesType.WPA,
}

RELATED_MATERIAL_TYPES: dict[str, RelatedCryptoMaterialType] = {
    "public-key": RelatedCryptoMaterialType.PUBLIC_KEY,
    "private-key": RelatedCryptoMaterialType.PRIVATE_KEY,
    "encrypted private key": RelatedCryptoMaterialType.PRIVATE_KEY,
    "secret-key": RelatedCryptoMaterialType.SECRET_KEY,
    "password": RelatedCryptoMaterialType.PASSWORD,
    "seed": RelatedCryptoMaterialType.SEED,
}

_ASSET_TYPES: dict[AssetType, CryptoAssetType] = {
    AssetType.ALGORITHM: CryptoAssetType.ALGORITHM,
    AssetType.CERTIFICATE: CryptoAssetType.CERTIFICATE,
    AssetType.PROTOCOL: CryptoAssetType.PROTOCOL,
    AssetType.RELATED_CRYPTO_MATERIAL: CryptoAssetType.RELATED_CRYPTO_MATERIAL,
}


def build_bom(
    assets: list[CryptoAsset],
    *,
    target_name: str = "scanned-codebase",
    tool_version: str = "0.1.0",
    serial_number: UUID | None = None,
    timestamp: datetime | None = None,
) -> Bom:
    bom = Bom()
    bom.metadata.tools.components.add(
        Component(
            name=TOOL_NAME,
            type=ComponentType.APPLICATION,
            group=TOOL_VENDOR,
            version=tool_version,
            bom_ref=f"{TOOL_NAME}@{tool_version}",
        )
    )
    root = Component(name=target_name, type=ComponentType.APPLICATION, bom_ref=target_name)
    bom.metadata.component = root
    if serial_number is not None:
        bom.serial_number = serial_number
    if timestamp is not None:
        bom.metadata.timestamp = timestamp

    components = [_component(asset) for asset in assets]
    for component in components:
        bom.components.add(component)
    bom.register_dependency(root, components)
    return bom


def to_json(
    bom: Bom, schema_version: SchemaVersion = DEFAULT_SCHEMA_VERSION, indent: int = 2
) -> str:
    outputter = make_outputter(bom, OutputFormat.JSON, schema_version)
    return json.dumps(json.loads(outputter.output_as_string()), indent=indent, sort_keys=True)


def validate(document: str, schema_version: SchemaVersion = DEFAULT_SCHEMA_VERSION) -> str | None:
    """Return None when the document is valid, or the validation error as a string."""
    problem = JsonStrictValidator(schema_version).validate_str(document)
    return None if problem is None else str(problem)


def generate(
    assets: list[CryptoAsset],
    schema_version: SchemaVersion = DEFAULT_SCHEMA_VERSION,
    **kwargs: Any,
) -> str:
    return to_json(build_bom(assets, **kwargs), schema_version)


# ------------------------------------------------------------------------- components


def _component(asset: CryptoAsset) -> Component:
    return Component(
        name=_name(asset),
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        bom_ref=f"crypto/{asset.asset_type.value}/{asset.algorithm}/{asset.asset_id}",
        description=_description(asset),
        crypto_properties=_crypto_properties(asset),
    )


def _name(asset: CryptoAsset) -> str:
    parts = [asset.algorithm]
    if asset.mode.value not in {"unknown", "other"}:
        parts.append(asset.mode.value.upper())
    if asset.parameter_set and asset.parameter_set != asset.algorithm:
        parts.append(asset.parameter_set)
    return "-".join(parts)


def _description(asset: CryptoAsset) -> str:
    count = asset.occurrence_count
    places = "1 place" if count == 1 else f"{count} places"
    return f"{asset.purpose.value} -- found in {places}, first at {asset.occurrences[0]}"


def _crypto_properties(asset: CryptoAsset) -> CryptoProperties:
    asset_type = _ASSET_TYPES[asset.asset_type]
    return CryptoProperties(
        asset_type=asset_type,
        oid=asset.oid,
        algorithm_properties=(
            _algorithm_properties(asset) if asset.asset_type is AssetType.ALGORITHM else None
        ),
        certificate_properties=(
            _certificate_properties(asset) if asset.asset_type is AssetType.CERTIFICATE else None
        ),
        related_crypto_material_properties=(
            _related_material_properties(asset)
            if asset.asset_type is AssetType.RELATED_CRYPTO_MATERIAL
            else None
        ),
        protocol_properties=(
            _protocol_properties(asset) if asset.asset_type is AssetType.PROTOCOL else None
        ),
    )


def _algorithm_properties(asset: CryptoAsset) -> AlgorithmProperties:
    return AlgorithmProperties(
        primitive=CryptoPrimitive(asset.primitive.value),
        parameter_set_identifier=(
            asset.parameter_set if asset.parameter_set != asset.curve else None
        ),
        curve=asset.curve,
        mode=CryptoMode(asset.mode.value),
        padding=CryptoPadding(asset.padding.value),
        crypto_functions=[CryptoFunction(f.value) for f in asset.crypto_functions],
        classical_security_level=asset.classical_security_level,
        nist_quantum_security_level=asset.nist_quantum_security_level,
    )


def _certificate_properties(asset: CryptoAsset) -> CertificateProperties:
    return CertificateProperties(
        subject_name=asset.details.get("subject"),
        issuer_name=asset.details.get("issuer"),
        not_valid_before=_date(asset.details.get("not_before")),
        not_valid_after=_date(asset.details.get("not_after")),
        certificate_format=_certificate_format(asset),
    )


def _certificate_format(asset: CryptoAsset) -> str | None:
    suffix = asset.files[0].rsplit(".", 1)[-1].lower()
    if suffix in {"der", "cer", "crt"}:
        return "DER"
    if suffix == "pem":
        return "PEM"
    return None


def _related_material_properties(asset: CryptoAsset) -> RelatedCryptoMaterialProperties:
    artifact = str(asset.details.get("artifact", ""))
    return RelatedCryptoMaterialProperties(
        type=RELATED_MATERIAL_TYPES.get(artifact, RelatedCryptoMaterialType.UNKNOWN),
        size=asset.key_size,
    )


def _protocol_properties(asset: CryptoAsset) -> ProtocolProperties:
    return ProtocolProperties(
        type=_protocol_type(asset.algorithm),
        version=asset.parameter_set,
    )


def _protocol_type(algorithm: str) -> ProtocolPropertiesType:
    """`TLS-unverified` is still TLS. A configuration weakness names the protocol it weakens,
    so the lookup falls back to the part before the first hyphen."""
    name = algorithm.upper()
    if name in PROTOCOL_TYPES:
        return PROTOCOL_TYPES[name]
    return PROTOCOL_TYPES.get(name.split("-", 1)[0], ProtocolPropertiesType.UNKNOWN)


def _date(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("unparseable certificate date %r", raw, exc_info=True)
        return None
