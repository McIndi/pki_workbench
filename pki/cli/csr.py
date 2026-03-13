from pathlib import Path

from pki import services

from .common import split_csv


def build_subject_from_args(args):
    subject = {
        'country_name': args.country_name,
        'state_or_province_name': args.state_or_province_name,
        'locality_name': args.locality_name,
        'organization_name': args.organization_name,
        'common_name': args.common_name,
        'organizational_unit_name': getattr(args, 'organizational_unit_name', ''),
        'email_address': getattr(args, 'email_address', ''),
    }
    return {key: value for key, value in subject.items() if value}


def generate_csr_from_args(args) -> str:
    required_fields = [
        'country_name',
        'state_or_province_name',
        'locality_name',
        'organization_name',
        'common_name',
    ]
    missing = [name for name in required_fields if not getattr(args, name)]
    if missing:
        missing_options = ', '.join('--' + name.replace('_', '-') for name in missing)
        raise SystemExit(f'Missing required subject fields for --generate-csr: {missing_options}')

    key_passphrase = args.csr_key_passphrase or None
    private_key_pem = services.create_private_key(
        key_algorithm=args.csr_key_algorithm,
        curve_name=args.csr_curve_name,
        key_size=args.csr_key_size,
        public_exponent=args.csr_public_exponent,
        passphrase=key_passphrase,
    )
    csr_bytes = services.create_csr(
        private_key_pem=private_key_pem,
        subject=build_subject_from_args(args),
        passphrase=key_passphrase,
        san_dns_names=split_csv(args.csr_san_dns_names),
    )

    if args.save_generated_key_file:
        Path(args.save_generated_key_file).write_bytes(private_key_pem)
        print(f'Saved generated private key: {args.save_generated_key_file}')

    if args.save_generated_csr_file:
        Path(args.save_generated_csr_file).write_bytes(csr_bytes)
        print(f'Saved generated CSR: {args.save_generated_csr_file}')

    return csr_bytes.decode('utf-8')
