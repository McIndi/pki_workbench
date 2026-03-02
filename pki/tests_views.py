from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from io import BytesIO
from zipfile import ZipFile

from .models import CertificateAuthority, CertificateProfile, SignedCertificate
from .workflows import create_intermediate_certificate_authority, create_root_certificate_authority, issue_signed_certificate


class PKIViewsTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create(email='viewer@example.com')
        self.user.set_password('safe-password-123')
        self.user.save(update_fields=['password'])

        self.subject = {
            'country_name': 'US',
            'state_or_province_name': 'New York',
            'locality_name': 'New York',
            'organization_name': 'PKI Workbench',
            'common_name': 'Root Via View',
        }

    def test_create_root_view_requires_login(self):
        response = self.client.get(reverse('pki-create-root-ca'))
        self.assertEqual(response.status_code, 302)

    def test_create_root_ca_view_success(self):
        self.client.force_login(self.user)

        response = self.client.post(
            reverse('pki-create-root-ca'),
            data={
                'name': 'View Root Authority',
                'certification_depth': 3,
                'days_valid': 3650,
                'key_algorithm': 'rsa',
                'curve_name': 'secp256r1',
                'key_size': 2048,
                'public_exponent': 65537,
                'passphrase': '',
                'country_name': 'US',
                'state_or_province_name': 'New York',
                'locality_name': 'New York',
                'organization_name': 'PKI Workbench',
                'common_name': 'View Root CA',
                'email_address': '',
            },
        )

        self.assertEqual(response.status_code, 302)
        root = CertificateAuthority.objects.get(name='View Root Authority', owner=self.user)
        self.assertRedirects(response, reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}))

    def test_workbench_issue_certificate_action(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Workbench Root',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={
                'action': 'issue_certificate',
                'issue-name': 'Issued From Workbench',
                'issue-days_valid': 365,
                'issue-key_algorithm': 'ec',
                'issue-curve_name': 'secp256r1',
                'issue-key_size': '',
                'issue-public_exponent': '',
                'issue-passphrase': '',
                'issue-issuer_key_passphrase': '',
                'issue-san_dns_names': 'service.example.com,api.example.com',
                'issue-country_name': 'US',
                'issue-state_or_province_name': 'New York',
                'issue-locality_name': 'New York',
                'issue-organization_name': 'PKI Workbench',
                'issue-common_name': 'service.example.com',
                'issue-email_address': '',
            },
        )

        self.assertEqual(response.status_code, 302)
        root.refresh_from_db()
        self.assertTrue(SignedCertificate.objects.filter(issued_by=root, name='Issued From Workbench').exists())

    def test_workbench_create_intermediate_action(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Workbench Root 2',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={
                'action': 'create_intermediate',
                'intermediate-name': 'Intermediate Via Workbench',
                'intermediate-days_valid': 1825,
                'intermediate-key_algorithm': 'rsa',
                'intermediate-curve_name': 'secp256r1',
                'intermediate-key_size': 2048,
                'intermediate-public_exponent': 65537,
                'intermediate-passphrase': '',
                'intermediate-parent_key_passphrase': '',
                'intermediate-country_name': 'US',
                'intermediate-state_or_province_name': 'New York',
                'intermediate-locality_name': 'New York',
                'intermediate-organization_name': 'PKI Workbench',
                'intermediate-common_name': 'Intermediate Via Workbench',
                'intermediate-email_address': '',
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            CertificateAuthority.objects.filter(name='Intermediate Via Workbench', owner=self.user, parent=root).exists()
        )

    def test_issued_certificate_detail_and_downloads(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Download Root',
            subject=self.subject,
            certification_depth=3,
        )
        issued = issue_signed_certificate(
            owner=self.user,
            issuer_authority=root,
            name='Service Cert 01',
            subject={
                **self.subject,
                'common_name': 'service01.example.com',
            },
            key_algorithm='rsa',
        )

        detail_response = self.client.get(
            reverse('pki-issued-certificate-detail', kwargs={'certificate_id': issued.pk})
        )
        self.assertEqual(detail_response.status_code, 200)

        pubcert_response = self.client.get(
            reverse('pki-issued-certificate-download', kwargs={'certificate_id': issued.pk, 'artifact': 'pubcert'})
        )
        self.assertEqual(pubcert_response.status_code, 200)
        self.assertIn('pubcert', pubcert_response['Content-Disposition'])

        chain_response = self.client.get(
            reverse('pki-issued-certificate-download', kwargs={'certificate_id': issued.pk, 'artifact': 'pubcert-chain'})
        )
        self.assertEqual(chain_response.status_code, 200)
        self.assertIn('pubcert', chain_response['Content-Disposition'])
        self.assertIn('BEGIN CERTIFICATE', chain_response.content.decode('utf-8'))

        csr_response = self.client.get(
            reverse('pki-issued-certificate-download', kwargs={'certificate_id': issued.pk, 'artifact': 'csr'})
        )
        self.assertEqual(csr_response.status_code, 200)
        self.assertIn('csr', csr_response['Content-Disposition'])

        pair_zip_response = self.client.get(
            reverse('pki-issued-certificate-download', kwargs={'certificate_id': issued.pk, 'artifact': 'pair-zip'})
        )
        self.assertEqual(pair_zip_response.status_code, 200)
        self.assertEqual(pair_zip_response['Content-Type'], 'application/zip')

        with ZipFile(BytesIO(pair_zip_response.content)) as archive:
            names = archive.namelist()
            self.assertTrue(any('pubcert' in name for name in names))
            self.assertTrue(any('privkey' in name for name in names))
            self.assertTrue(any('csr' in name for name in names))

    def test_issued_certificate_downloads_are_owner_scoped(self):
        user_model = get_user_model()
        other_user = user_model.objects.create(email='other@example.com')
        other_user.set_password('safe-password-123')
        other_user.save(update_fields=['password'])

        root = create_root_certificate_authority(
            owner=other_user,
            name='Other User Root',
            subject=self.subject,
            certification_depth=3,
        )
        issued = issue_signed_certificate(
            owner=other_user,
            issuer_authority=root,
            name='Other User Cert',
            subject={
                **self.subject,
                'common_name': 'other.example.com',
            },
        )

        self.client.force_login(self.user)
        response = self.client.get(
            reverse('pki-issued-certificate-download', kwargs={'certificate_id': issued.pk, 'artifact': 'pubcert'})
        )
        self.assertEqual(response.status_code, 404)

    def test_workbench_create_certificate_profile_action(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Profile Root',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={
                'action': 'create_certificate_profile',
                'profile-name': 'Web Server Profile',
                'profile-description': 'TLS server profile',
                'profile-is_ca': '',
                'profile-path_length': '',
                'profile-days_valid': 825,
                'profile-key_algorithm': 'rsa',
                'profile-curve_name': 'secp256r1',
                'profile-key_size': 2048,
                'profile-public_exponent': 65537,
                'profile-country_name': 'US',
                'profile-state_or_province_name': 'New York',
                'profile-locality_name': 'New York',
                'profile-organization_name': 'PKI Workbench',
                'profile-organizational_unit_name': 'Infrastructure',
                'profile-common_name': '',
                'profile-email_address': '',
                'profile-ku_digital_signature': 'on',
                'profile-ku_content_commitment': '',
                'profile-ku_key_encipherment': 'on',
                'profile-ku_data_encipherment': '',
                'profile-ku_key_agreement': '',
                'profile-ku_key_cert_sign': '',
                'profile-ku_crl_sign': '',
                'profile-ku_encipher_only': '',
                'profile-ku_decipher_only': '',
                'profile-ku_critical': 'on',
                'profile-eku_server_auth': 'on',
                'profile-eku_client_auth': '',
                'profile-eku_code_signing': '',
                'profile-eku_email_protection': '',
                'profile-eku_time_stamping': '',
                'profile-eku_ocsp_signing': '',
            },
        )

        self.assertEqual(response.status_code, 302)
        profile = CertificateProfile.objects.get(owner=self.user, name='Web Server Profile')
        self.assertEqual(profile.organization_name, 'PKI Workbench')
        self.assertEqual(profile.organizational_unit_name, 'Infrastructure')

    def test_create_profile_from_certificate_detail(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Derive Profile Root',
            subject=self.subject,
            certification_depth=3,
        )
        issued = issue_signed_certificate(
            owner=self.user,
            issuer_authority=root,
            name='Profile Source Cert',
            subject={
                **self.subject,
                'common_name': 'source.example.com',
            },
            key_algorithm='ec',
            curve_name='secp384r1',
        )

        response = self.client.post(
            reverse('pki-issued-certificate-detail', kwargs={'certificate_id': issued.pk}),
            data={
                'from-cert-name': 'Derived from Source Cert',
                'from-cert-description': 'Auto-captured from issued cert',
            },
        )

        self.assertEqual(response.status_code, 302)
        profile = CertificateProfile.objects.get(owner=self.user, name='Derived from Source Cert')
        self.assertEqual(profile.key_algorithm, 'ec')
        self.assertEqual(profile.curve_name, 'secp384r1')
        self.assertEqual(profile.organization_name, 'PKI Workbench')
        self.assertEqual(profile.common_name, 'source.example.com')

    def test_workbench_profile_fields_render_as_dropdowns(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Dropdown Root',
            subject=self.subject,
            certification_depth=3,
        )
        profile = CertificateProfile.objects.create(
            owner=self.user,
            name='Visual Feedback Profile',
            key_algorithm='ec',
            curve_name='secp384r1',
            days_valid=400,
            organization_name='Pinned Org',
            organizational_unit_name='Security',
        )

        response = self.client.get(reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode('utf-8')
        self.assertIn('name="profile-key_algorithm"', html)
        self.assertIn('<option value="rsa"', html)
        self.assertIn('<option value="ec"', html)
        self.assertIn('name="profile-curve_name"', html)
        self.assertIn('<option value="secp384r1"', html)
        self.assertIn('id="issue-profile-payload"', html)
        self.assertIn(f'"{profile.pk}"', html)
        self.assertIn('name="issue-organizational_unit_name"', html)
        self.assertIn('name="profile-organizational_unit_name"', html)
        self.assertIn('"organization_name": "Pinned Org"', html)
        self.assertIn('data-profile-bound', html)

    def test_profile_tab_remains_active_on_invalid_profile_submit(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Invalid Profile Root',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={
                'action': 'create_certificate_profile',
                'profile-name': '',
            },
        )
        self.assertEqual(response.status_code, 200)
        html = response.content.decode('utf-8')
        self.assertIn('nav-link active" id="profile-tab"', html)
        self.assertIn('show active" id="profile-pane" role="tabpanel"', html)

    def test_workbench_lists_existing_profiles_with_edit_controls(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Profile Listing Root',
            subject=self.subject,
            certification_depth=3,
        )
        profile = CertificateProfile.objects.create(
            owner=self.user,
            name='Existing Profile',
            description='Shown in profile list',
            key_algorithm='rsa',
        )

        response = self.client.get(reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode('utf-8')
        self.assertIn('Certificate Profiles', html)
        self.assertIn('data-profile-nav-dropdown', html)
        self.assertIn('data-profile-nav-search', html)
        self.assertIn('Existing Profile', html)
        self.assertIn(reverse('pki-profile-edit', kwargs={'profile_id': profile.pk}), html)

    def test_profile_edit_view_updates_profile_and_returns_to_workbench(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Profile Edit Root',
            subject=self.subject,
            certification_depth=3,
        )
        profile = CertificateProfile.objects.create(
            owner=self.user,
            name='Editable Profile',
            description='Before update',
            key_algorithm='rsa',
            organization_name='Old Org',
        )

        response = self.client.post(
            reverse('pki-profile-edit', kwargs={'profile_id': profile.pk}),
            data={
                'ca_id': str(root.pk),
                'profile-name': 'Editable Profile Updated',
                'profile-description': 'After update',
                'profile-is_ca': '',
                'profile-path_length': '',
                'profile-days_valid': 700,
                'profile-key_algorithm': 'ec',
                'profile-curve_name': 'secp384r1',
                'profile-key_size': '',
                'profile-public_exponent': 65537,
                'profile-country_name': 'US',
                'profile-state_or_province_name': 'New York',
                'profile-locality_name': 'New York',
                'profile-organization_name': 'New Org',
                'profile-organizational_unit_name': 'Security',
                'profile-common_name': '',
                'profile-email_address': '',
                'profile-ku_digital_signature': 'on',
                'profile-ku_content_commitment': '',
                'profile-ku_key_encipherment': 'on',
                'profile-ku_data_encipherment': '',
                'profile-ku_key_agreement': '',
                'profile-ku_key_cert_sign': '',
                'profile-ku_crl_sign': '',
                'profile-ku_encipher_only': '',
                'profile-ku_decipher_only': '',
                'profile-ku_critical': 'on',
                'profile-eku_server_auth': 'on',
                'profile-eku_client_auth': '',
                'profile-eku_code_signing': '',
                'profile-eku_email_protection': '',
                'profile-eku_time_stamping': '',
                'profile-eku_ocsp_signing': '',
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}))
        profile.refresh_from_db()
        self.assertEqual(profile.name, 'Editable Profile Updated')
        self.assertEqual(profile.key_algorithm, 'ec')
        self.assertEqual(profile.curve_name, 'secp384r1')
        self.assertEqual(profile.organization_name, 'New Org')
        self.assertEqual(profile.organizational_unit_name, 'Security')

    def test_home_dashboard_shows_counts_and_expiring_certificates(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Home Root',
            subject=self.subject,
            certification_depth=3,
        )
        CertificateProfile.objects.create(owner=self.user, name='Home Profile')
        issue_signed_certificate(
            owner=self.user,
            issuer_authority=root,
            name='Home Cert Soon',
            subject={**self.subject, 'common_name': 'soon.example.com'},
            days_valid=10,
        )
        issue_signed_certificate(
            owner=self.user,
            issuer_authority=root,
            name='Home Cert Later',
            subject={**self.subject, 'common_name': 'later.example.com'},
            days_valid=90,
        )

        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode('utf-8')
        self.assertIn('PKI Dashboard', html)
        self.assertIn('Certificate Authorities', html)
        self.assertIn('Issued Certificates', html)
        self.assertIn('Certificate Profiles', html)
        self.assertIn('Home Cert Soon', html)
        self.assertIn('Home Cert Later', html)

    def test_home_dashboard_shows_recursive_ca_tree(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Tree Root',
            subject=self.subject,
            certification_depth=3,
        )
        intermediate = create_intermediate_certificate_authority(
            owner=self.user,
            parent_authority=root,
            name='Tree Intermediate',
            subject={**self.subject, 'common_name': 'Tree Intermediate'},
        )

        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode('utf-8')
        self.assertIn('CA Hierarchy', html)
        self.assertIn('Tree Root', html)
        self.assertIn('Tree Intermediate', html)
        self.assertIn(reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}), html)
        self.assertIn(reverse('pki-ca-workbench', kwargs={'ca_id': intermediate.pk}), html)
