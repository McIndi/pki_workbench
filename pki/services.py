from datetime import datetime, timedelta, timezone
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa, x25519, x448
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID


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
    if key_algorithm == 'rsa':
        private_key = rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)
    elif key_algorithm == 'ec':
        curve_class = EC_CURVE_MAP.get(curve_name)
        if curve_class is None:
            raise ValueError(f'Unsupported EC curve: {curve_name}')
        private_key = ec.generate_private_key(curve_class())
    elif key_algorithm == 'eddsa':
        if curve_name == 'ed25519':
            private_key = ed25519.Ed25519PrivateKey.generate()
        elif curve_name == 'ed448':
            private_key = ed448.Ed448PrivateKey.generate()
        else:
            raise ValueError(f'Unsupported EdDSA curve: {curve_name}')
    elif key_algorithm == 'x25519':
        private_key = x25519.X25519PrivateKey.generate()
    elif key_algorithm == 'x448':
        private_key = x448.X448PrivateKey.generate()
    else:
        raise ValueError(f'Unsupported key algorithm: {key_algorithm}')
    if passphrase is not None:
        passphrase_bytes = _passphrase_to_bytes(passphrase)
        if passphrase_bytes is None:
            raise ValueError('Passphrase could not be parsed.')
        encryption = serialization.BestAvailableEncryption(passphrase_bytes)
    else:
        encryption = serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
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
    return (
        x509.KeyUsage(
            digital_signature=bool(key_usage.get('digital_signature', False)),
            content_commitment=bool(key_usage.get('content_commitment', False)),
            key_encipherment=bool(key_usage.get('key_encipherment', False)),
            data_encipherment=bool(key_usage.get('data_encipherment', False)),
            key_agreement=key_agreement,
            key_cert_sign=bool(key_usage.get('key_cert_sign', False)),
            crl_sign=bool(key_usage.get('crl_sign', False)),
            encipher_only=bool(key_usage.get('encipher_only', False)) if key_agreement else False,
            decipher_only=bool(key_usage.get('decipher_only', False)) if key_agreement else False,
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
    private_key = load_private_key(private_key_pem, passphrase=passphrase)
    if not isinstance(private_key, ISSUER_PRIVATE_KEY_TYPES):
        raise TypeError('Unsupported key type for CSR signing.')
    issuer_private_key = cast(
        rsa.RSAPrivateKey
        | dsa.DSAPrivateKey
        | ec.EllipticCurvePrivateKey
        | ed25519.Ed25519PrivateKey
        | ed448.Ed448PrivateKey,
        private_key,
    )

    builder = x509.CertificateSigningRequestBuilder().subject_name(_to_subject_name(subject))

    if san_dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns_names]),
            critical=False,
        )

    csr = builder.sign(issuer_private_key, _sign_algorithm_for_private_key(issuer_private_key))
    return csr.public_bytes(serialization.Encoding.PEM)


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
