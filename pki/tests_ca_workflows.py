from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase
from django.contrib.auth import get_user_model
from cryptography import x509

from . import services
from .models import CertificateAuthority, CertificateProfile, CertificateSigningRequest, PrivateKey, SignedCertificate
from .workflows import create_intermediate_certificate_authority, create_root_certificate_authority, issue_signed_certificate


class CertificateAuthorityWorkflowTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user_one = User.objects.create(email='owner1@example.com')
        self.user_one.set_password('safe-password-123')
        self.user_one.save(update_fields=['password'])

        self.user_two = User.objects.create(email='owner2@example.com')
        self.user_two.set_password('safe-password-123')
        self.user_two.save(update_fields=['password'])

        self.root_subject = {
            'country_name': 'US',
            'state_or_province_name': 'New York',
            'locality_name': 'New York',
            'organization_name': 'PKI Workbench',
            'common_name': 'PKI Root CA',
        }

    def test_create_root_certificate_authority(self):
        root = create_root_certificate_authority(
            owner=self.user_one,
            name='Root Authority',
            subject=self.root_subject,
            certification_depth=3,
            key_algorithm='rsa',
            days_valid=3650,
        )

        self.assertTrue(root.is_root)
        self.assertEqual(root.owner, self.user_one)
        self.assertEqual(root.depth, 0)
        self.assertEqual(root.certification_depth, 3)
        self.assertEqual(root.private_key.algorithm, PrivateKey.Algorithm.RSA)
        self.assertEqual(root.certificate.private_key, root.private_key)

    def test_create_intermediate_certificate_authority(self):
        root = create_root_certificate_authority(
            owner=self.user_one,
            name='Root Authority',
            subject=self.root_subject,
            certification_depth=3,
        )

        intermediate = create_intermediate_certificate_authority(
            owner=self.user_one,
            parent_authority=root,
            name='Intermediate Authority',
            subject={**self.root_subject, 'common_name': 'Intermediate CA'},
            key_algorithm='ec',
            curve_name='secp384r1',
        )

        self.assertEqual(intermediate.parent, root)
        self.assertEqual(intermediate.owner, self.user_one)
        self.assertEqual(intermediate.depth, 1)
        self.assertEqual(intermediate.certification_depth, 3)
        self.assertTrue(
            services.verify_certificate_signature(
                certificate_pem=intermediate.certificate.certificate_pem.encode('utf-8'),
                issuer_certificate_pem=root.certificate.certificate_pem.encode('utf-8'),
            )
        )
        self.assertEqual(CertificateSigningRequest.objects.count(), 1)

    def test_reject_intermediate_beyond_certification_depth(self):
        root = create_root_certificate_authority(
            owner=self.user_one,
            name='Root Authority',
            subject=self.root_subject,
            certification_depth=1,
        )

        with self.assertRaises(ValidationError):
            create_intermediate_certificate_authority(
                owner=self.user_one,
                parent_authority=root,
                name='Too Deep Intermediate',
                subject={**self.root_subject, 'common_name': 'Too Deep Intermediate CA'},
            )

    def test_models_are_persisted_for_chain(self):
        root = create_root_certificate_authority(
            owner=self.user_one,
            name='Root Persisted Authority',
            subject=self.root_subject,
            certification_depth=3,
        )
        create_intermediate_certificate_authority(
            owner=self.user_one,
            parent_authority=root,
            name='Intermediate Persisted Authority',
            subject={**self.root_subject, 'common_name': 'Persisted Intermediate CA'},
        )

        self.assertEqual(CertificateAuthority.objects.count(), 2)
        self.assertEqual(PrivateKey.objects.count(), 2)
        self.assertEqual(SignedCertificate.objects.count(), 2)
        self.assertEqual(CertificateSigningRequest.objects.count(), 1)

    def test_same_ca_name_allowed_for_different_users(self):
        create_root_certificate_authority(
            owner=self.user_one,
            name='Shared Name Root',
            subject=self.root_subject,
            certification_depth=3,
        )
        create_root_certificate_authority(
            owner=self.user_two,
            name='Shared Name Root',
            subject={**self.root_subject, 'common_name': 'Other User Root'},
            certification_depth=3,
        )

        self.assertEqual(CertificateAuthority.objects.filter(name='Shared Name Root').count(), 2)

    def test_duplicate_ca_name_rejected_for_same_user(self):
        create_root_certificate_authority(
            owner=self.user_one,
            name='Duplicate Name Root',
            subject=self.root_subject,
            certification_depth=3,
        )

        with self.assertRaises(IntegrityError):
            create_root_certificate_authority(
                owner=self.user_one,
                name='Duplicate Name Root',
                subject={**self.root_subject, 'common_name': 'Duplicate CN'},
                certification_depth=3,
            )

    def test_issue_certificate_with_profile_sets_extensions(self):
        root = create_root_certificate_authority(
            owner=self.user_one,
            name='Root For Profile',
            subject=self.root_subject,
            certification_depth=3,
        )
        profile = CertificateProfile.objects.create(
            owner=self.user_one,
            name='Mutual TLS Client',
            description='Client-auth cert profile',
            key_algorithm='ec',
            curve_name='secp384r1',
            ku_digital_signature=True,
            ku_key_encipherment=False,
            ku_key_agreement=True,
            eku_server_auth=False,
            eku_client_auth=True,
        )

        issued = issue_signed_certificate(
            owner=self.user_one,
            issuer_authority=root,
            name='Client Cert from Profile',
            subject={**self.root_subject, 'common_name': 'client.example.com'},
            certificate_profile=profile,
        )

        certificate = x509.load_pem_x509_certificate(issued.certificate_pem.encode('utf-8'))
        key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        extended_key_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value

        self.assertTrue(key_usage.digital_signature)
        self.assertTrue(key_usage.key_agreement)
        self.assertFalse(key_usage.key_encipherment)
        self.assertIn(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, extended_key_usage)
        self.assertNotIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, extended_key_usage)

    def test_issue_certificate_with_profile_enforces_subject_constraints(self):
        root = create_root_certificate_authority(
            owner=self.user_one,
            name='Root For Subject Constraints',
            subject=self.root_subject,
            certification_depth=3,
        )
        profile = CertificateProfile.objects.create(
            owner=self.user_one,
            name='Pinned Subject Profile',
            organization_name='Pinned Org',
            organizational_unit_name='Security',
            state_or_province_name='California',
        )

        issued = issue_signed_certificate(
            owner=self.user_one,
            issuer_authority=root,
            name='Cert With Pinned Subject',
            subject={
                **self.root_subject,
                'organization_name': 'User Supplied Org',
                'state_or_province_name': 'Nevada',
                'common_name': 'pinned.example.com',
            },
            certificate_profile=profile,
        )

        self.assertEqual(issued.csr.subject['organization_name'], 'Pinned Org')
        self.assertEqual(issued.csr.subject['organizational_unit_name'], 'Security')
        self.assertEqual(issued.csr.subject['state_or_province_name'], 'California')
