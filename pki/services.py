from datetime import datetime, timedelta, timezone
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa, x25519, x448
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID
from pki_shared.crypto import create_csr as shared_create_csr
from pki_shared.crypto import create_private_key as shared_create_private_key


SUBJECT_FIELD_MAP = {
    'country_name': NameOID.COUNTRY_NAME,
    'state_or_province_name': NameOID.STATE_OR_PROVINCE_NAME,
    'locality_name': NameOID.LOCALITY_NAME,
    'organization_name': NameOID.ORGANIZATION_NAME,
    'organizational_unit_name': NameOID.ORGANIZATIONAL_UNIT_NAME,
    'common_name': NameOID.COMMON_NAME,
    'email_address': NameOID.EMAIL_ADDRESS,
}

ISSUER_PRIVATE_KEY_TYPES = (
    rsa.RSAPrivateKey,
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
)

ISSUER_PUBLIC_KEY_TYPES = (
    rsa.RSAPublicKey,
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
)

KEY_AGREEMENT_PRIVATE_KEY_TYPES = (
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
)

KEY_AGREEMENT_PUBLIC_KEY_TYPES = (
    x25519.X25519PublicKey,
    x448.X448PublicKey,
)

EC_CURVE_MAP = {
    'secp256r1': ec.SECP256R1,
    'secp384r1': ec.SECP384R1,
    'secp521r1': ec.SECP521R1,
    'brainpoolP256r1': ec.BrainpoolP256R1,
    'brainpoolP384r1': ec.BrainpoolP384R1,
    'brainpoolP512r1': ec.BrainpoolP512R1,
    'secp256k1': ec.SECP256K1,
}

EXTENDED_KEY_USAGE_MAP = {
    'server_auth': ExtendedKeyUsageOID.SERVER_AUTH,
    'client_auth': ExtendedKeyUsageOID.CLIENT_AUTH,
    'code_signing': ExtendedKeyUsageOID.CODE_SIGNING,
    'email_protection': ExtendedKeyUsageOID.EMAIL_PROTECTION,
    'time_stamping': ExtendedKeyUsageOID.TIME_STAMPING,
    'ocsp_signing': ExtendedKeyUsageOID.OCSP_SIGNING,
}

KEY_USAGE_DISPLAY_MAP = {
    'digital_signature': 'Digital Signature',
    'content_commitment': 'Content Commitment',
    'key_encipherment': 'Key Encipherment',
    'data_encipherment': 'Data Encipherment',
    'key_agreement': 'Key Agreement',
    'key_cert_sign': 'Key Cert Sign',
    'crl_sign': 'CRL Sign',
    'encipher_only': 'Encipher Only',
    'decipher_only': 'Decipher Only',
}

EXTENDED_KEY_USAGE_DISPLAY_MAP = {
    ExtendedKeyUsageOID.SERVER_AUTH: 'Server Auth',
    ExtendedKeyUsageOID.CLIENT_AUTH: 'Client Auth',
    ExtendedKeyUsageOID.CODE_SIGNING: 'Code Signing',
    ExtendedKeyUsageOID.EMAIL_PROTECTION: 'Email Protection',
    ExtendedKeyUsageOID.TIME_STAMPING: 'Time Stamping',
    ExtendedKeyUsageOID.OCSP_SIGNING: 'OCSP Signing',
}


def _to_subject_name(subject: dict) -> x509.Name:
    attributes = []
    for field_name, oid in SUBJECT_FIELD_MAP.items():
        value = subject.get(field_name)
        if value:
            attributes.append(x509.NameAttribute(oid, value))

    if not attributes:
        raise ValueError('Subject must include at least one valid X.509 name attribute.')

    return x509.Name(attributes)


def _passphrase_to_bytes(passphrase: str | bytes | bytearray | memoryview | None) -> bytes | None:
    if passphrase is None:
        return None
    if isinstance(passphrase, str):
        return passphrase.encode('utf-8')
    return bytes(passphrase)


def create_private_key(
    *,
    passphrase: str | bytes | bytearray | memoryview | None = None,
    key_algorithm: str = 'rsa',
    curve_name: str = 'secp256r1',
    key_size: int = 2048,
    public_exponent: int = 65537,
) -> bytes:
    return shared_create_private_key(
        passphrase=passphrase,
        key_algorithm=key_algorithm,
        curve_name=curve_name,
        key_size=key_size,
        public_exponent=public_exponent,
    )


def load_private_key(private_key_pem: bytes, *, passphrase: str | bytes | bytearray | memoryview | None = None):
    return serialization.load_pem_private_key(private_key_pem, password=_passphrase_to_bytes(passphrase))


def get_public_key_pem(
    private_key_pem: bytes,
    *,
    passphrase: str | bytes | bytearray | memoryview | None = None,
) -> bytes:
    private_key = load_private_key(private_key_pem, passphrase=passphrase)
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def derive_shared_secret(
    *,
    private_key_pem: bytes,
    peer_public_key_pem: bytes,
    passphrase: str | bytes | bytearray | memoryview | None = None,
) -> bytes:
    private_key = load_private_key(private_key_pem, passphrase=passphrase)
    peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)

    if isinstance(private_key, x25519.X25519PrivateKey) and isinstance(peer_public_key, x25519.X25519PublicKey):
        return private_key.exchange(peer_public_key)

    if isinstance(private_key, x448.X448PrivateKey) and isinstance(peer_public_key, x448.X448PublicKey):
        return private_key.exchange(peer_public_key)

    if isinstance(private_key, KEY_AGREEMENT_PRIVATE_KEY_TYPES) or isinstance(peer_public_key, KEY_AGREEMENT_PUBLIC_KEY_TYPES):
        raise TypeError('Key agreement keys must be from the same curve family.')

    raise TypeError('Shared secret derivation supports only X25519 and X448 keys.')


def _sign_algorithm_for_private_key(private_key):
    if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return None
    return hashes.SHA256()


def _normalize_key_usage(key_usage: dict | None, *, is_ca: bool) -> tuple[x509.KeyUsage, bool]:
    if key_usage is None:
        if is_ca:
            return (
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
        return (
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )

    key_agreement = bool(key_usage.get('key_agreement', False))
    key_usage_flags = {
        'digital_signature': bool(key_usage.get('digital_signature', False)),
        'content_commitment': bool(key_usage.get('content_commitment', False)),
        'key_encipherment': bool(key_usage.get('key_encipherment', False)),
        'data_encipherment': bool(key_usage.get('data_encipherment', False)),
        'key_agreement': key_agreement,
        'key_cert_sign': bool(key_usage.get('key_cert_sign', False)),
        'crl_sign': bool(key_usage.get('crl_sign', False)),
        'encipher_only': bool(key_usage.get('encipher_only', False)) if key_agreement else False,
        'decipher_only': bool(key_usage.get('decipher_only', False)) if key_agreement else False,
    }
    if not any(key_usage_flags.values()):
        raise ValueError('At least one Key Usage bit must be set.')

    return (
        x509.KeyUsage(
            digital_signature=key_usage_flags['digital_signature'],
            content_commitment=key_usage_flags['content_commitment'],
            key_encipherment=key_usage_flags['key_encipherment'],
            data_encipherment=key_usage_flags['data_encipherment'],
            key_agreement=key_usage_flags['key_agreement'],
            key_cert_sign=key_usage_flags['key_cert_sign'],
            crl_sign=key_usage_flags['crl_sign'],
            encipher_only=key_usage_flags['encipher_only'],
            decipher_only=key_usage_flags['decipher_only'],
        ),
        bool(key_usage.get('critical', True)),
    )


def _normalize_extended_key_usage(extended_key_usages: list[str] | None) -> x509.ExtendedKeyUsage | None:
    if not extended_key_usages:
        return None
    oids = []
    for usage in extended_key_usages:
        oid = EXTENDED_KEY_USAGE_MAP.get(usage)
        if oid is not None:
            oids.append(oid)
    if not oids:
        return None
    return x509.ExtendedKeyUsage(oids)


def create_csr(
    *,
    private_key_pem: bytes,
    subject: dict,
    passphrase: str | bytes | bytearray | memoryview | None = None,
    san_dns_names: list[str] | None = None,
) -> bytes:
    return shared_create_csr(
        private_key_pem=private_key_pem,
        subject=subject,
        passphrase=passphrase,
        san_dns_names=san_dns_names,
    )


def create_self_signed_ca(
    *,
    private_key_pem: bytes,
    subject: dict,
    passphrase: str | bytes | bytearray | memoryview | None = None,
    days_valid: int = 3650,
    path_length: int | None = None,
    key_usage: dict | None = None,
    extended_key_usages: list[str] | None = None,
) -> bytes:
    """Build and self-sign a new CA certificate for *subject*, returning it PEM-encoded."""
    private_key = load_private_key(private_key_pem, passphrase=passphrase)
    if not isinstance(private_key, ISSUER_PRIVATE_KEY_TYPES):
        raise TypeError('Unsupported key type for CA certificate signing.')
    issuer_private_key = cast(
        rsa.RSAPrivateKey
        | dsa.DSAPrivateKey
        | ec.EllipticCurvePrivateKey
        | ed25519.Ed25519PrivateKey
        | ed448.Ed448PrivateKey,
        private_key,
    )
    issuer_public_key = cast(
        rsa.RSAPublicKey
        | dsa.DSAPublicKey
        | ec.EllipticCurvePublicKey
        | ed25519.Ed25519PublicKey
        | ed448.Ed448PublicKey,
        issuer_private_key.public_key(),
    )
    subject_name = _to_subject_name(subject)
    now = datetime.now(timezone.utc)

    normalized_key_usage, key_usage_critical = _normalize_key_usage(key_usage, is_ca=True)
    normalized_extended_key_usage = _normalize_extended_key_usage(extended_key_usages)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(issuer_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(normalized_key_usage, critical=key_usage_critical)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key), critical=False)
    )

    if normalized_extended_key_usage is not None:
        certificate = certificate.add_extension(normalized_extended_key_usage, critical=False)

    certificate = certificate.sign(private_key=issuer_private_key, algorithm=_sign_algorithm_for_private_key(issuer_private_key))

    return certificate.public_bytes(serialization.Encoding.PEM)


def sign_certificate(
    *,
    csr_pem: bytes,
    ca_cert_pem: bytes,
    ca_private_key_pem: bytes,
    ca_passphrase: str | bytes | bytearray | memoryview | None = None,
    days_valid: int = 365,
    is_ca: bool = False,
    path_length: int | None = None,
    key_usage: dict | None = None,
    extended_key_usages: list[str] | None = None,
) -> bytes:
    """Sign *csr_pem* with the given CA's key/certificate and return the issued certificate PEM-encoded."""
    csr = x509.load_pem_x509_csr(csr_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_private_key = load_private_key(ca_private_key_pem, passphrase=ca_passphrase)
    if not isinstance(ca_private_key, ISSUER_PRIVATE_KEY_TYPES):
        raise TypeError('Unsupported CA private key type for certificate issuance.')
    issuer_private_key = cast(
        rsa.RSAPrivateKey
        | dsa.DSAPrivateKey
        | ec.EllipticCurvePrivateKey
        | ed25519.Ed25519PrivateKey
        | ed448.Ed448PrivateKey,
        ca_private_key,
    )

    ca_public_key = ca_cert.public_key()
    if not isinstance(ca_public_key, ISSUER_PUBLIC_KEY_TYPES):
        raise TypeError('Unsupported CA public key type for authority key identifier extension.')

    issuer_public_key = cast(
        rsa.RSAPublicKey
        | dsa.DSAPublicKey
        | ec.EllipticCurvePublicKey
        | ed25519.Ed25519PublicKey
        | ed448.Ed448PublicKey,
        ca_public_key,
    )
    now = datetime.now(timezone.utc)

    normalized_key_usage, key_usage_critical = _normalize_key_usage(key_usage, is_ca=is_ca)
    normalized_extended_key_usage = _normalize_extended_key_usage(extended_key_usages)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=path_length if is_ca else None), critical=True)
        .add_extension(normalized_key_usage, critical=key_usage_critical)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key), critical=False)
    )

    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san.value, critical=False)
    except x509.ExtensionNotFound:
        pass

    if normalized_extended_key_usage is not None:
        builder = builder.add_extension(normalized_extended_key_usage, critical=False)

    certificate = builder.sign(
        private_key=issuer_private_key,
        algorithm=_sign_algorithm_for_private_key(issuer_private_key),
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def validate_certificate_key_pair(
    *,
    certificate_pem: bytes,
    private_key_pem: bytes,
    passphrase: str | bytes | bytearray | memoryview | None = None,
) -> bool:
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    private_key = load_private_key(private_key_pem, passphrase=passphrase)
    return certificate.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_certificate_signature(*, certificate_pem: bytes, issuer_certificate_pem: bytes) -> bool:
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    issuer_certificate = x509.load_pem_x509_certificate(issuer_certificate_pem)
    issuer_public_key = issuer_certificate.public_key()

    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            if certificate.signature_hash_algorithm is None:
                return False
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, dsa.DSAPublicKey):
            if certificate.signature_hash_algorithm is None:
                return False
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                certificate.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            if certificate.signature_hash_algorithm is None:
                return False
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        elif isinstance(issuer_public_key, ed25519.Ed25519PublicKey):
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
        elif isinstance(issuer_public_key, ed448.Ed448PublicKey):
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
        else:
            return False
    except Exception:
        return False

    return certificate.issuer == issuer_certificate.subject


def parse_certificate_info(certificate_pem: bytes) -> dict:
    """Parse a PEM-encoded certificate into a dict of subject, validity, and serial number fields."""
    certificate = x509.load_pem_x509_certificate(certificate_pem)

    subject = {
        'country_name': _name_value(certificate.subject, NameOID.COUNTRY_NAME),
        'state_or_province_name': _name_value(certificate.subject, NameOID.STATE_OR_PROVINCE_NAME),
        'locality_name': _name_value(certificate.subject, NameOID.LOCALITY_NAME),
        'organization_name': _name_value(certificate.subject, NameOID.ORGANIZATION_NAME),
        'organizational_unit_name': _name_value(certificate.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        'common_name': _name_value(certificate.subject, NameOID.COMMON_NAME),
        'email_address': _name_value(certificate.subject, NameOID.EMAIL_ADDRESS),
    }

    issuer = {
        'country_name': _name_value(certificate.issuer, NameOID.COUNTRY_NAME),
        'state_or_province_name': _name_value(certificate.issuer, NameOID.STATE_OR_PROVINCE_NAME),
        'locality_name': _name_value(certificate.issuer, NameOID.LOCALITY_NAME),
        'organization_name': _name_value(certificate.issuer, NameOID.ORGANIZATION_NAME),
        'organizational_unit_name': _name_value(certificate.issuer, NameOID.ORGANIZATIONAL_UNIT_NAME),
        'common_name': _name_value(certificate.issuer, NameOID.COMMON_NAME),
        'email_address': _name_value(certificate.issuer, NameOID.EMAIL_ADDRESS),
    }

    return {
        'serial_number': str(certificate.serial_number),
        'subject': subject,
        'issuer': issuer,
        'not_valid_before': certificate.not_valid_before_utc.isoformat(),
        'not_valid_after': certificate.not_valid_after_utc.isoformat(),
        'signature_algorithm_oid': certificate.signature_algorithm_oid.dotted_string,
    }


def parse_csr_info(csr_pem: bytes) -> dict:
    csr = x509.load_pem_x509_csr(csr_pem)
    subject = {
        'country_name': _name_value(csr.subject, NameOID.COUNTRY_NAME),
        'state_or_province_name': _name_value(csr.subject, NameOID.STATE_OR_PROVINCE_NAME),
        'locality_name': _name_value(csr.subject, NameOID.LOCALITY_NAME),
        'organization_name': _name_value(csr.subject, NameOID.ORGANIZATION_NAME),
        'organizational_unit_name': _name_value(csr.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        'common_name': _name_value(csr.subject, NameOID.COMMON_NAME),
        'email_address': _name_value(csr.subject, NameOID.EMAIL_ADDRESS),
    }
    return {
        'subject': subject,
    }


def summarize_certificate_extensions(certificate_pem: str | bytes) -> dict:
    certificate_bytes = certificate_pem.encode('utf-8') if isinstance(certificate_pem, str) else certificate_pem
    certificate = x509.load_pem_x509_certificate(certificate_bytes)

    summary = {
        'basic_constraints': None,
        'key_usage': None,
        'extended_key_usage': None,
        'san_dns_names': [],
    }

    try:
        basic_constraints_ext = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        basic_constraints = basic_constraints_ext.value
        summary['basic_constraints'] = {
            'ca': basic_constraints.ca,
            'path_length': basic_constraints.path_length,
            'critical': basic_constraints_ext.critical,
        }
    except x509.ExtensionNotFound:
        pass

    try:
        key_usage_ext = certificate.extensions.get_extension_for_class(x509.KeyUsage)
        key_usage = key_usage_ext.value
        key_agreement = key_usage.key_agreement
        key_usage_flags = {
            'digital_signature': key_usage.digital_signature,
            'content_commitment': key_usage.content_commitment,
            'key_encipherment': key_usage.key_encipherment,
            'data_encipherment': key_usage.data_encipherment,
            'key_agreement': key_agreement,
            'key_cert_sign': key_usage.key_cert_sign,
            'crl_sign': key_usage.crl_sign,
            'encipher_only': key_usage.encipher_only if key_agreement else False,
            'decipher_only': key_usage.decipher_only if key_agreement else False,
        }
        summary['key_usage'] = {
            'critical': key_usage_ext.critical,
            'enabled': [
                KEY_USAGE_DISPLAY_MAP[field_name]
                for field_name, enabled in key_usage_flags.items()
                if enabled
            ],
        }
    except x509.ExtensionNotFound:
        pass

    try:
        extended_key_usage_ext = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        extended_key_usage = extended_key_usage_ext.value
        summary['extended_key_usage'] = {
            'critical': extended_key_usage_ext.critical,
            'enabled': [
                EXTENDED_KEY_USAGE_DISPLAY_MAP.get(oid, oid.dotted_string)
                for oid in extended_key_usage
            ],
        }
    except x509.ExtensionNotFound:
        pass

    try:
        subject_alt_name = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        summary['san_dns_names'] = subject_alt_name.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    return summary


def validate_ca_certificate(certificate_pem: bytes) -> None:
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not basic_constraints.ca:
        raise ValueError('Provided certificate is not a CA certificate.')


def _name_value(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    if not attrs:
        return None
    value = attrs[0].value
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    if isinstance(value, bytearray):
        return bytes(value).decode('utf-8', errors='replace')
    if isinstance(value, memoryview):
        return value.tobytes().decode('utf-8', errors='replace')
    return value
