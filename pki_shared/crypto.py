from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, x25519, x448
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

EC_CURVE_MAP = {
    'secp256r1': ec.SECP256R1,
    'secp384r1': ec.SECP384R1,
    'secp521r1': ec.SECP521R1,
    'brainpoolP256r1': ec.BrainpoolP256R1,
    'brainpoolP384r1': ec.BrainpoolP384R1,
    'brainpoolP512r1': ec.BrainpoolP512R1,
    'secp256k1': ec.SECP256K1,
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


def _sign_algorithm_for_private_key(private_key):
    if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return None
    return hashes.SHA256()


def load_private_key(private_key_pem: bytes, *, passphrase: str | bytes | bytearray | memoryview | None = None):
    return serialization.load_pem_private_key(private_key_pem, password=_passphrase_to_bytes(passphrase))


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
