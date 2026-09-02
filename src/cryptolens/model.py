from dataclasses import dataclass

@dataclass
class CryptoPurpose:
    ENCRYPTION = "Encryption"
    KEY_ESTABLISHMENT = "key_establishment"
    DIGITAL_SIGNATURE = 'digital_signature'
    HASHING = 'hashing'


@dataclass
class CryptoStatus:
    CLASSICAL = "classical"
    PQC = "pqc"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"

@dataclass
class RiskLevel:
    pass

@dataclass
class SourceLocation:
    file: str
    line: str
    
    

@dataclass
class CryptoFinding:
    pass