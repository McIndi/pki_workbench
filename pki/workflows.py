from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.dateparse import parse_datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import services
from .models import CertificateAuthority, CertificateProfile, CertificateSigningRequest, PrivateKey, SignedCertificate


def _decode_pem(pem_bytes: bytes) -> str:
    return pem_bytes.decode('utf-8')


def _parse_certificate_dates(certificate_pem: bytes) -> tuple:
    info = services.parse_certificate_info(certificate_pem)
    not_valid_before = parse_datetime(info['not_valid_before'])
    not_valid_after = parse_datetime(info['not_valid_after'])
    if not_valid_before is None or not_valid_after is None:
        raise ValidationError('Unable to parse certificate validity period.')
    return info, not_valid_before, not_valid_after


def _remaining_path_length(root_certification_depth: int, authority_depth: int) -> int | None:
    remaining_intermediate_levels = root_certification_depth - authority_depth - 1
    if remaining_intermediate_levels < 0:
        raise ValidationError('Certificate authority depth exceeds root certification depth.')
    return remaining_intermediate_levels


def _validate_profile_subject_constraints(subject: dict, profile: CertificateProfile) -> None:
    for field_name, expected in profile.subject_payload().items():
        actual = subject.get(field_name)
        if actual != expected:
            raise ValidationError(f'CSR subject does not match profile constraint for {field_name}.')


@transaction.atomic
def create_root_certificate_authority(
    *,
    owner,
    name: str,
    subject: dict,
    certification_depth: int = 3,
    key_algorithm: str = 'rsa',
    curve_name: str = 'secp256r1',
    key_size: int = 2048,
    public_exponent: int = 65537,
    passphrase: str | bytes | bytearray | memoryview | None = None,
    days_valid: int = 3650,
) -> CertificateAuthority:
    if owner is None:
        raise ValidationError('Owner is required.')

    if certification_depth < 1:
        raise ValidationError('Certification depth must be at least 1.')

    private_key_pem = services.create_private_key(
        passphrase=passphrase,
        key_algorithm=key_algorithm,
        curve_name=curve_name,
        key_size=key_size,
        public_exponent=public_exponent,
    )

    path_length = _remaining_path_length(certification_depth, 0)
    certificate_pem = services.create_self_signed_ca(
        private_key_pem=private_key_pem,
        subject=subject,
        passphrase=passphrase,
        days_valid=days_valid,
        path_length=path_length,
    )

    private_key = PrivateKey.objects.create(
        name=f'{name} key',
        owner=owner,
        algorithm=key_algorithm,
        curve_name=curve_name if key_algorithm != 'rsa' else '',
        key_size=key_size if key_algorithm == 'rsa' else None,
        is_encrypted=passphrase is not None,
        private_key_pem=_decode_pem(private_key_pem),
    )

    cert_info, not_valid_before, not_valid_after = _parse_certificate_dates(certificate_pem)
    signed_certificate = SignedCertificate.objects.create(
        name=f'{name} self-signed certificate',
        owner=owner,
        certificate_pem=_decode_pem(certificate_pem),
        serial_number=cert_info['serial_number'],
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        issued_by=None,
        private_key=private_key,
    )

    return CertificateAuthority.objects.create(
        name=name,
        owner=owner,
        parent=None,
        depth=0,
        certification_depth=certification_depth,
        private_key=private_key,
        certificate=signed_certificate,
    )


@transaction.atomic
def create_intermediate_certificate_authority(
    *,
    owner,
    parent_authority: CertificateAuthority,
    name: str,
    subject: dict,
    key_algorithm: str = 'rsa',
    curve_name: str = 'secp256r1',
    key_size: int = 2048,
    public_exponent: int = 65537,
    passphrase: str | bytes | bytearray | memoryview | None = None,
    parent_key_passphrase: str | bytes | bytearray | memoryview | None = None,
    days_valid: int = 1825,
) -> CertificateAuthority:
    if owner is None:
        raise ValidationError('Owner is required.')

    if parent_authority.owner != owner:
        raise ValidationError('Parent certificate authority does not belong to this owner.')

    root = parent_authority.root
    new_depth = parent_authority.depth + 1
    if new_depth > (root.certification_depth - 1):
        raise ValidationError(
            'Cannot create intermediate certificate authority beyond root certification depth.'
        )

    private_key_pem = services.create_private_key(
        passphrase=passphrase,
        key_algorithm=key_algorithm,
        curve_name=curve_name,
        key_size=key_size,
        public_exponent=public_exponent,
    )

    csr_pem = services.create_csr(
        private_key_pem=private_key_pem,
        subject=subject,
        passphrase=passphrase,
    )

    certificate_pem = services.sign_certificate(
        csr_pem=csr_pem,
        ca_cert_pem=parent_authority.certificate.certificate_pem.encode('utf-8'),
        ca_private_key_pem=parent_authority.private_key.private_key_pem.encode('utf-8'),
        ca_passphrase=parent_key_passphrase,
        days_valid=days_valid,
        is_ca=True,
        path_length=_remaining_path_length(root.certification_depth, new_depth),
    )

    private_key = PrivateKey.objects.create(
        name=f'{name} key',
        owner=owner,
        algorithm=key_algorithm,
        curve_name=curve_name if key_algorithm != 'rsa' else '',
        key_size=key_size if key_algorithm == 'rsa' else None,
        is_encrypted=passphrase is not None,
        private_key_pem=_decode_pem(private_key_pem),
    )

    csr = CertificateSigningRequest.objects.create(
        name=f'{name} csr',
        owner=owner,
        private_key=private_key,
        subject=subject,
        csr_pem=_decode_pem(csr_pem),
    )

    cert_info, not_valid_before, not_valid_after = _parse_certificate_dates(certificate_pem)
    signed_certificate = SignedCertificate.objects.create(
        name=f'{name} certificate',
        owner=owner,
        certificate_pem=_decode_pem(certificate_pem),
        serial_number=cert_info['serial_number'],
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        issued_by=parent_authority,
        private_key=private_key,
        csr=csr,
    )

    return CertificateAuthority.objects.create(
        name=name,
        owner=owner,
        parent=parent_authority,
        depth=new_depth,
        certification_depth=root.certification_depth,
        private_key=private_key,
        certificate=signed_certificate,
    )


@transaction.atomic
def issue_signed_certificate(
    *,
    owner,
    issuer_authority: CertificateAuthority,
    name: str,
    subject: dict,
    key_algorithm: str = 'rsa',
    curve_name: str = 'secp256r1',
    key_size: int = 2048,
    public_exponent: int = 65537,
    certificate_profile: CertificateProfile | None = None,
    passphrase: str | bytes | bytearray | memoryview | None = None,
    issuer_key_passphrase: str | bytes | bytearray | memoryview | None = None,
    days_valid: int = 365,
    san_dns_names: list[str] | None = None,
    key_usage: dict | None = None,
    extended_key_usages: list[str] | None = None,
) -> SignedCertificate:
    if owner is None:
        raise ValidationError('Owner is required.')
    if issuer_authority.owner != owner:
        raise ValidationError('Issuer certificate authority does not belong to this owner.')

    if certificate_profile is not None:
        if certificate_profile.owner not in {None, owner}:
            raise ValidationError('Certificate profile does not belong to this owner.')
        key_algorithm = certificate_profile.key_algorithm
        curve_name = certificate_profile.curve_name or curve_name
        key_size = certificate_profile.key_size or key_size
        public_exponent = certificate_profile.public_exponent or public_exponent
        days_valid = certificate_profile.days_valid or days_valid
        key_usage = certificate_profile.key_usage_payload()
        extended_key_usages = certificate_profile.extended_key_usage_payload()
        subject = {
            **subject,
            **certificate_profile.subject_payload(),
        }

    private_key_pem = services.create_private_key(
        passphrase=passphrase,
        key_algorithm=key_algorithm,
        curve_name=curve_name,
        key_size=key_size,
        public_exponent=public_exponent,
    )

    csr_pem = services.create_csr(
        private_key_pem=private_key_pem,
        subject=subject,
        passphrase=passphrase,
        san_dns_names=san_dns_names,
    )

    certificate_pem = services.sign_certificate(
        csr_pem=csr_pem,
        ca_cert_pem=issuer_authority.certificate.certificate_pem.encode('utf-8'),
        ca_private_key_pem=issuer_authority.private_key.private_key_pem.encode('utf-8'),
        ca_passphrase=issuer_key_passphrase,
        days_valid=days_valid,
        is_ca=False,
        key_usage=key_usage,
        extended_key_usages=extended_key_usages,
    )

    private_key = PrivateKey.objects.create(
        name=f'{name} key',
        owner=owner,
        algorithm=key_algorithm,
        curve_name=curve_name if key_algorithm != 'rsa' else '',
        key_size=key_size if key_algorithm == 'rsa' else None,
        is_encrypted=passphrase is not None,
        private_key_pem=_decode_pem(private_key_pem),
    )

    csr = CertificateSigningRequest.objects.create(
        name=f'{name} csr',
        owner=owner,
        private_key=private_key,
        subject=subject,
        csr_pem=_decode_pem(csr_pem),
    )

    cert_info, not_valid_before, not_valid_after = _parse_certificate_dates(certificate_pem)
    return SignedCertificate.objects.create(
        name=name,
        owner=owner,
        certificate_pem=_decode_pem(certificate_pem),
        serial_number=cert_info['serial_number'],
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        issued_by=issuer_authority,
        private_key=private_key,
        csr=csr,
    )


@transaction.atomic
def issue_signed_certificate_from_csr(
    *,
    owner,
    issuer_authority: CertificateAuthority,
    name: str,
    csr_pem: str | bytes,
    certificate_profile: CertificateProfile | None = None,
    issuer_key_passphrase: str | bytes | bytearray | memoryview | None = None,
    days_valid: int = 365,
    key_usage: dict | None = None,
    extended_key_usages: list[str] | None = None,
) -> SignedCertificate:
    if owner is None:
        raise ValidationError('Owner is required.')
    if issuer_authority.owner != owner:
        raise ValidationError('Issuer certificate authority does not belong to this owner.')

    csr_bytes = csr_pem.encode('utf-8') if isinstance(csr_pem, str) else csr_pem
    parsed_csr = services.parse_csr_info(csr_bytes)

    if certificate_profile is not None:
        if certificate_profile.owner not in {None, owner}:
            raise ValidationError('Certificate profile does not belong to this owner.')
        days_valid = certificate_profile.days_valid or days_valid
        key_usage = certificate_profile.key_usage_payload()
        extended_key_usages = certificate_profile.extended_key_usage_payload()
        _validate_profile_subject_constraints(parsed_csr['subject'], certificate_profile)

    certificate_pem = services.sign_certificate(
        csr_pem=csr_bytes,
        ca_cert_pem=issuer_authority.certificate.certificate_pem.encode('utf-8'),
        ca_private_key_pem=issuer_authority.private_key.private_key_pem.encode('utf-8'),
        ca_passphrase=issuer_key_passphrase,
        days_valid=days_valid,
        is_ca=False,
        key_usage=key_usage,
        extended_key_usages=extended_key_usages,
    )

    csr_record = CertificateSigningRequest.objects.create(
        name=f'{name} csr',
        owner=owner,
        private_key=None,
        subject=parsed_csr['subject'],
        csr_pem=_decode_pem(csr_bytes),
    )

    cert_info, not_valid_before, not_valid_after = _parse_certificate_dates(certificate_pem)
    return SignedCertificate.objects.create(
        name=name,
        owner=owner,
        certificate_pem=_decode_pem(certificate_pem),
        serial_number=cert_info['serial_number'],
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        issued_by=issuer_authority,
        private_key=None,
        csr=csr_record,
    )


@transaction.atomic
def import_certificate_authority(
    *,
    owner,
    name: str,
    certificate_pem: str | bytes,
    private_key_pem: str | bytes,
    key_passphrase: str | bytes | bytearray | memoryview | None = None,
    certification_depth: int = 3,
    parent_authority: CertificateAuthority | None = None,
) -> CertificateAuthority:
    if owner is None:
        raise ValidationError('Owner is required.')
    if certification_depth < 1:
        raise ValidationError('Certification depth must be at least 1.')

    cert_bytes = certificate_pem.encode('utf-8') if isinstance(certificate_pem, str) else certificate_pem
    key_bytes = private_key_pem.encode('utf-8') if isinstance(private_key_pem, str) else private_key_pem

    try:
        services.validate_ca_certificate(cert_bytes)
    except Exception as exc:
        raise ValidationError(f'Invalid CA certificate: {exc}') from exc

    if not services.validate_certificate_key_pair(
        certificate_pem=cert_bytes,
        private_key_pem=key_bytes,
        passphrase=key_passphrase,
    ):
        raise ValidationError('Private key does not match provided CA certificate.')

    loaded_key = services.load_private_key(key_bytes, passphrase=key_passphrase)
    if isinstance(loaded_key, rsa.RSAPrivateKey):
        key_algorithm = 'rsa'
        curve_name = ''
        key_size = loaded_key.key_size
    elif isinstance(loaded_key, ec.EllipticCurvePrivateKey):
        key_algorithm = 'ec'
        curve_name = loaded_key.curve.name
        key_size = None
    elif isinstance(loaded_key, ed25519.Ed25519PrivateKey):
        key_algorithm = 'eddsa'
        curve_name = 'ed25519'
        key_size = None
    elif isinstance(loaded_key, ed448.Ed448PrivateKey):
        key_algorithm = 'eddsa'
        curve_name = 'ed448'
        key_size = None
    else:
        raise ValidationError('Unsupported private key type for CA import.')

    parsed = x509.load_pem_x509_certificate(cert_bytes)
    is_self_signed = parsed.subject == parsed.issuer and services.verify_certificate_signature(
        certificate_pem=cert_bytes,
        issuer_certificate_pem=cert_bytes,
    )

    if parent_authority is not None:
        if parent_authority.owner != owner:
            raise ValidationError('Parent certificate authority does not belong to this owner.')
        if not services.verify_certificate_signature(
            certificate_pem=cert_bytes,
            issuer_certificate_pem=parent_authority.certificate.certificate_pem.encode('utf-8'),
        ):
            raise ValidationError('Imported CA certificate is not signed by selected parent authority.')
        depth = parent_authority.depth + 1
        root_certification_depth = parent_authority.root.certification_depth
        if depth > (root_certification_depth - 1):
            raise ValidationError('Imported CA depth exceeds root certification depth.')
        certification_depth = root_certification_depth
    else:
        if not is_self_signed:
            raise ValidationError('Non-root CA import requires selecting a parent authority.')
        depth = 0

    private_key_obj = PrivateKey.objects.create(
        name=f'{name} key',
        owner=owner,
        algorithm=key_algorithm,
        curve_name=curve_name,
        key_size=key_size,
        is_encrypted=bool(key_passphrase),
        private_key_pem=_decode_pem(key_bytes),
    )

    cert_info, not_valid_before, not_valid_after = _parse_certificate_dates(cert_bytes)
    signed_certificate = SignedCertificate.objects.create(
        name=f'{name} certificate',
        owner=owner,
        certificate_pem=_decode_pem(cert_bytes),
        serial_number=cert_info['serial_number'],
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
        issued_by=parent_authority,
        private_key=private_key_obj,
        csr=None,
    )

    return CertificateAuthority.objects.create(
        name=name,
        owner=owner,
        parent=parent_authority,
        depth=depth,
        certification_depth=certification_depth,
        private_key=private_key_obj,
        certificate=signed_certificate,
    )


EKU_OID_TO_NAME = {
    ExtendedKeyUsageOID.SERVER_AUTH: 'eku_server_auth',
    ExtendedKeyUsageOID.CLIENT_AUTH: 'eku_client_auth',
    ExtendedKeyUsageOID.CODE_SIGNING: 'eku_code_signing',
    ExtendedKeyUsageOID.EMAIL_PROTECTION: 'eku_email_protection',
    ExtendedKeyUsageOID.TIME_STAMPING: 'eku_time_stamping',
    ExtendedKeyUsageOID.OCSP_SIGNING: 'eku_ocsp_signing',
}


@transaction.atomic
def create_certificate_profile_from_certificate(
    *,
    owner,
    certificate: SignedCertificate,
    name: str,
    description: str = '',
) -> CertificateProfile:
    if owner is None:
        raise ValidationError('Owner is required.')
    if certificate.owner != owner:
        raise ValidationError('Certificate does not belong to this owner.')

    parsed_certificate = x509.load_pem_x509_certificate(certificate.certificate_pem.encode('utf-8'))
    validity_days = max((certificate.not_valid_after - certificate.not_valid_before).days, 1)

    profile_data = {
        'name': name,
        'owner': owner,
        'description': description,
        'days_valid': validity_days,
        'key_algorithm': certificate.private_key.algorithm,
        'curve_name': certificate.private_key.curve_name or 'secp256r1',
        'key_size': certificate.private_key.key_size or 2048,
        'public_exponent': 65537,
        'country_name': '',
        'state_or_province_name': '',
        'locality_name': '',
        'organization_name': '',
        'organizational_unit_name': '',
        'common_name': '',
        'email_address': '',
        'is_ca': False,
        'path_length': None,
        'ku_digital_signature': True,
        'ku_content_commitment': False,
        'ku_key_encipherment': True,
        'ku_data_encipherment': False,
        'ku_key_agreement': False,
        'ku_key_cert_sign': False,
        'ku_crl_sign': False,
        'ku_encipher_only': False,
        'ku_decipher_only': False,
        'ku_critical': True,
        'eku_server_auth': False,
        'eku_client_auth': False,
        'eku_code_signing': False,
        'eku_email_protection': False,
        'eku_time_stamping': False,
        'eku_ocsp_signing': False,
    }

    try:
        basic_constraints = parsed_certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        profile_data['is_ca'] = basic_constraints.ca
        profile_data['path_length'] = basic_constraints.path_length
    except x509.ExtensionNotFound:
        pass

    try:
        key_usage = parsed_certificate.extensions.get_extension_for_class(x509.KeyUsage)
        key_usage_value = key_usage.value
        key_agreement = key_usage_value.key_agreement
        profile_data.update(
            {
                'ku_digital_signature': key_usage_value.digital_signature,
                'ku_content_commitment': key_usage_value.content_commitment,
                'ku_key_encipherment': key_usage_value.key_encipherment,
                'ku_data_encipherment': key_usage_value.data_encipherment,
                'ku_key_agreement': key_agreement,
                'ku_key_cert_sign': key_usage_value.key_cert_sign,
                'ku_crl_sign': key_usage_value.crl_sign,
                'ku_encipher_only': key_usage_value.encipher_only if key_agreement else False,
                'ku_decipher_only': key_usage_value.decipher_only if key_agreement else False,
                'ku_critical': key_usage.critical,
            }
        )
    except x509.ExtensionNotFound:
        pass

    try:
        extended_key_usage = parsed_certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        for oid in extended_key_usage:
            field_name = EKU_OID_TO_NAME.get(oid)
            if field_name is not None:
                profile_data[field_name] = True
    except x509.ExtensionNotFound:
        pass

    subject_mapping = {
        NameOID.COUNTRY_NAME: 'country_name',
        NameOID.STATE_OR_PROVINCE_NAME: 'state_or_province_name',
        NameOID.LOCALITY_NAME: 'locality_name',
        NameOID.ORGANIZATION_NAME: 'organization_name',
        NameOID.ORGANIZATIONAL_UNIT_NAME: 'organizational_unit_name',
        NameOID.COMMON_NAME: 'common_name',
        NameOID.EMAIL_ADDRESS: 'email_address',
    }
    for attribute in parsed_certificate.subject:
        field_name = subject_mapping.get(attribute.oid)
        if field_name is not None:
            profile_data[field_name] = attribute.value

    return CertificateProfile.objects.create(**profile_data)
