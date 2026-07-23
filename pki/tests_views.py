from django.contrib.auth import get_user_model
from django.contrib.staticfiles import finders
from django.test import TestCase
from django.urls import reverse
from io import BytesIO
from zipfile import ZipFile

from . import services
from .models import CertificateAuthority, CertificateProfile, SignedCertificate
from .workflows import create_intermediate_certificate_authority, create_root_certificate_authority, issue_signed_certificate, issue_signed_certificate_from_csr


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

    def test_create_root_view_can_import_existing_ca(self):
        self.client.force_login(self.user)
        private_key_pem = services.create_private_key(key_algorithm='rsa', key_size=2048)
        certificate_pem = services.create_self_signed_ca(
            private_key_pem=private_key_pem,
            subject={
                'country_name': 'US',
                'state_or_province_name': 'New York',
                'locality_name': 'New York',
                'organization_name': 'PKI Workbench',
                'common_name': 'Imported View Root',
            },
            days_valid=3650,
            path_length=2,
        )

        response = self.client.post(
            reverse('pki-create-root-ca'),
            data={
                'action': 'import_ca',
                'name': 'Imported View Root',
                'certificate_pem': certificate_pem.decode('utf-8'),
                'private_key_pem': private_key_pem.decode('utf-8'),
                'key_passphrase': '',
                'certification_depth': 3,
                'parent_ca': '',
            },
        )

        self.assertEqual(response.status_code, 302)
        imported = CertificateAuthority.objects.get(owner=self.user, name='Imported View Root')
        self.assertRedirects(response, reverse('pki-ca-workbench', kwargs={'ca_id': imported.pk}))

    def test_workbench_post_unified_issue_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Unified Issue Root',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'unified_issue'},
        )
        self.assertEqual(response.status_code, 405)

    def test_workbench_unified_form_exposes_api_endpoint_metadata(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Unified Metadata Root',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.get(reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-unified-form')
        self.assertContains(response, f'data-ca-id="{root.pk}"')
        self.assertContains(response, 'data-endpoint-issue="/api/workflows/certificates/"')
        self.assertContains(response, 'data-endpoint-intermediate="/api/workflows/intermediate-cas/"')

    def test_workbench_script_refreshes_after_non_intermediate_success(self):
        script_path = finders.find('pki/workbench.js')

        self.assertIsNotNone(script_path)
        with open(script_path, encoding='utf-8') as handle:
            script = handle.read()

        self.assertIn("Request completed successfully. Refreshing workbench...", script)
        self.assertIn('window.location.assign(window.location.href);', script)

    def test_workbench_unified_form_includes_ca_mode_leaf_usage_note(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Unified CA Mode Note Root',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.get(reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-leaf-options')
        self.assertContains(
            response,
            'CA certificates always use Digital Signature, Key Cert Sign, and CRL Sign (critical).',
        )

    def test_workbench_unified_form_highlights_leaf_usage_recommended_defaults(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Unified Recommended Defaults Root',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.get(reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-default-leaf-usage-hint')
        self.assertContains(
            response,
            'Defaults for a typical TLS server certificate are pre-selected: Digital Signature, Key Encipherment, Critical, and Server Auth. Adjust as needed.',
        )
        self.assertContains(response, 'data-reset-leaf-defaults')
        self.assertContains(response, 'Reset to recommended defaults')

    def test_workbench_profile_form_exposes_api_endpoint_metadata(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Profile Metadata Root',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.get(reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-profile-form')
        self.assertContains(response, 'data-api-endpoint="/api/profiles/"')

    def test_workbench_manage_tab_explicitly_states_account_wide_scope(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Manage Scope Root',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.get(reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Manage All Objects')
        self.assertContains(
            response,
            f'This tab lists every CA, certificate, private key, and CSR in your account. It is not limited to objects under {root.name}.',
        )

    def test_workbench_manage_tab_delete_forms_include_api_action_and_return_target(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Manage Delete Fallback Root',
            subject=self.subject,
            certification_depth=3,
        )
        certificate = issue_signed_certificate(
            owner=self.user,
            issuer_authority=root,
            name='Manage Delete Fallback Cert',
            subject={**self.subject, 'common_name': 'manage-delete-fallback.example.com'},
        )

        response = self.client.get(reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'action="/api/workflows/delete-certificate/"')
        self.assertContains(response, f'name="next" value="/pki/ca/{root.pk}/workbench/?tab=manage"')
        self.assertContains(response, f'name="certificate_id" value="{certificate.pk}"')

    def test_workbench_honors_manage_tab_query_parameter(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Manage Tab Query Root',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.get(f"{reverse('pki-ca-workbench', kwargs={'ca_id': root.pk})}?tab=manage")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<button class="nav-link active" id="manage-tab"', html=False)

    def test_delete_certificate_workflow_form_post_redirects_back_to_manage_tab(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Delete Redirect Root',
            subject=self.subject,
            certification_depth=3,
        )
        certificate = issue_signed_certificate(
            owner=self.user,
            issuer_authority=root,
            name='Delete Redirect Cert',
            subject={**self.subject, 'common_name': 'delete-redirect.example.com'},
        )
        manage_url = f"{reverse('pki-ca-workbench', kwargs={'ca_id': root.pk})}?tab=manage"

        response = self.client.post(
            reverse('api-workflow-delete-certificate'),
            data={'certificate_id': certificate.pk, 'next': manage_url},
            follow=True,
        )

        self.assertEqual(response.redirect_chain, [(manage_url, 302)])
        self.assertEqual(response.status_code, 200)
        self.assertFalse(SignedCertificate.objects.filter(pk=certificate.pk).exists())
        self.assertContains(response, 'Certificate deleted successfully.')
        self.assertContains(response, '<button class="nav-link active" id="manage-tab"', html=False)

    def test_workbench_post_unified_issue_signs_csr_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Unified CSR Root',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'unified_issue'},
        )
        self.assertEqual(response.status_code, 405)

    def test_workbench_post_unified_issue_issuer_passphrase_fallback_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Unified Fallback Root',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'unified_issue'},
        )
        self.assertEqual(response.status_code, 405)

    def test_workbench_post_unified_issue_encrypted_parent_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Encrypted Parent Root',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'unified_issue'},
        )
        self.assertEqual(response.status_code, 405)

    def test_workbench_post_unified_issue_encrypted_issuer_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Encrypted Issuer Root',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'unified_issue'},
        )
        self.assertEqual(response.status_code, 405)

    def test_workbench_post_delete_certificate_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Delete Cert Root',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'delete_certificate'},
        )
        self.assertEqual(response.status_code, 405)

    def test_workbench_post_delete_csr_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Delete CSR Root',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'delete_csr'},
        )
        self.assertEqual(response.status_code, 405)

    def test_workbench_post_delete_private_key_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Delete Private Key Root',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'delete_private_key'},
        )
        self.assertEqual(response.status_code, 405)

    def test_workbench_post_delete_ca_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Delete Me CA',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'delete_ca'},
        )
        self.assertEqual(response.status_code, 405)

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

    def test_issued_certificate_detail_displays_leaf_extensions(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Extension Display Root',
            subject=self.subject,
            certification_depth=3,
        )
        issued = issue_signed_certificate(
            owner=self.user,
            issuer_authority=root,
            name='Extension Display Cert',
            subject={
                **self.subject,
                'common_name': 'extensions.example.com',
            },
            san_dns_names=['extensions.example.com', 'www.extensions.example.com'],
            key_usage={
                'digital_signature': True,
                'content_commitment': False,
                'key_encipherment': True,
                'data_encipherment': False,
                'key_agreement': False,
                'key_cert_sign': False,
                'crl_sign': False,
                'encipher_only': False,
                'decipher_only': False,
                'critical': True,
            },
            extended_key_usages=['server_auth', 'client_auth'],
        )

        response = self.client.get(
            reverse('pki-issued-certificate-detail', kwargs={'certificate_id': issued.pk})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Certificate Extensions')
        self.assertContains(response, 'CA: No')
        self.assertContains(response, 'Digital Signature')
        self.assertContains(response, 'Key Encipherment')
        self.assertContains(response, 'Server Auth')
        self.assertContains(response, 'Client Auth')
        self.assertContains(response, 'www.extensions.example.com')

    def test_issued_certificate_detail_displays_ca_basic_constraints(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Root Extension Display',
            subject=self.subject,
            certification_depth=3,
        )

        response = self.client.get(
            reverse('pki-issued-certificate-detail', kwargs={'certificate_id': root.certificate.pk})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Certificate Extensions')
        self.assertContains(response, 'CA: Yes')
        self.assertContains(response, 'Path Length:')
        self.assertContains(response, '2')
        self.assertContains(response, 'Key Cert Sign')
        self.assertContains(response, 'CRL Sign')

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

    def test_pair_zip_download_returns_404_when_private_key_not_stored(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='No Key Zip Root',
            subject=self.subject,
            certification_depth=3,
        )
        requester_key_pem = services.create_private_key(key_algorithm='rsa', key_size=2048)
        requester_csr_pem = services.create_csr(
            private_key_pem=requester_key_pem,
            subject={
                'country_name': 'US',
                'state_or_province_name': 'New York',
                'locality_name': 'New York',
                'organization_name': 'PKI Workbench',
                'common_name': 'zip-missing-key.example.com',
            },
        )

        certificate = issue_signed_certificate_from_csr(
            owner=self.user,
            issuer_authority=root,
            name='CSR Without Stored Key',
            csr_pem=requester_csr_pem,
            days_valid=365,
        )
        response = self.client.get(
            reverse('pki-issued-certificate-download', kwargs={'certificate_id': certificate.pk, 'artifact': 'pair-zip'})
        )
        self.assertEqual(response.status_code, 404)

    def test_workbench_post_create_certificate_profile_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Profile Root',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'create_certificate_profile'},
        )
        self.assertEqual(response.status_code, 405)

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
        self.assertIn('name="unified-organizational_unit_name"', html)
        self.assertIn('name="profile-organizational_unit_name"', html)
        self.assertIn('"organization_name": "Pinned Org"', html)
        self.assertIn('data-profile-bound', html)

    def test_workbench_post_invalid_profile_submit_returns_405(self):
        """CAWorkbenchView is now GET-only; POST returns 405."""
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user, name='Invalid Profile Root',
            subject=self.subject, certification_depth=3,
        )
        response = self.client.post(
            reverse('pki-ca-workbench', kwargs={'ca_id': root.pk}),
            data={'action': 'create_certificate_profile', 'profile-name': ''},
        )
        self.assertEqual(response.status_code, 405)

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

    def test_create_profile_from_certificate_detail_returns_400_for_csr_issued_certificate(self):
        self.client.force_login(self.user)
        root = create_root_certificate_authority(
            owner=self.user,
            name='Derive Profile CSR Root',
            subject=self.subject,
            certification_depth=3,
        )
        requester_key_pem = services.create_private_key(key_algorithm='rsa', key_size=2048)
        requester_csr_pem = services.create_csr(
            private_key_pem=requester_key_pem,
            subject={
                **self.subject,
                'common_name': 'csr-source.example.com',
            },
        )
        issued = issue_signed_certificate_from_csr(
            owner=self.user,
            issuer_authority=root,
            name='CSR Profile Source',
            csr_pem=requester_csr_pem,
            days_valid=365,
        )

        response = self.client.post(
            reverse('pki-issued-certificate-detail', kwargs={'certificate_id': issued.pk}),
            data={
                'from-cert-name': 'Derived from CSR Source',
                'from-cert-description': 'Should fail because private key is not stored',
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertContains(
            response,
            'Cannot derive a profile from a certificate with no stored private key (CSR-issued certificates do not retain one).',
            status_code=400,
        )

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
