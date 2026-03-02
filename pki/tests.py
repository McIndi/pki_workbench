from django.test import SimpleTestCase

from . import services


class PKIServicesTests(SimpleTestCase):
	def setUp(self):
		self.subject = {
			'country_name': 'US',
			'state_or_province_name': 'New York',
			'locality_name': 'New York',
			'organization_name': 'PKI Workbench',
			'common_name': 'example.com',
		}

	def test_create_private_key_without_passphrase(self):
		private_key_pem = services.create_private_key()
		self.assertIn(b'BEGIN PRIVATE KEY', private_key_pem)

	def test_create_private_key_with_passphrase(self):
		private_key_pem = services.create_private_key(passphrase='top-secret')
		self.assertIn(b'BEGIN ENCRYPTED PRIVATE KEY', private_key_pem)

	def test_create_csr(self):
		private_key_pem = services.create_private_key()
		csr_pem = services.create_csr(
			private_key_pem=private_key_pem,
			subject=self.subject,
			san_dns_names=['example.com', 'www.example.com'],
		)
		self.assertIn(b'BEGIN CERTIFICATE REQUEST', csr_pem)

	def test_sign_certificate_from_ca(self):
		ca_key_pem = services.create_private_key()
		ca_cert_pem = services.create_self_signed_ca(
			private_key_pem=ca_key_pem,
			subject={**self.subject, 'common_name': 'Example Test CA'},
			days_valid=3650,
		)

		leaf_key_pem = services.create_private_key()
		csr_pem = services.create_csr(private_key_pem=leaf_key_pem, subject=self.subject)
		cert_pem = services.sign_certificate(
			csr_pem=csr_pem,
			ca_cert_pem=ca_cert_pem,
			ca_private_key_pem=ca_key_pem,
			days_valid=365,
		)

		self.assertIn(b'BEGIN CERTIFICATE', cert_pem)

	def test_validate_certificate_and_key_pair(self):
		ca_key_pem = services.create_private_key()
		ca_cert_pem = services.create_self_signed_ca(
			private_key_pem=ca_key_pem,
			subject={**self.subject, 'common_name': 'Example Root CA'},
			days_valid=3650,
		)

		leaf_key_pem = services.create_private_key()
		csr_pem = services.create_csr(private_key_pem=leaf_key_pem, subject=self.subject)
		cert_pem = services.sign_certificate(
			csr_pem=csr_pem,
			ca_cert_pem=ca_cert_pem,
			ca_private_key_pem=ca_key_pem,
			days_valid=365,
		)

		is_match = services.validate_certificate_key_pair(
			certificate_pem=cert_pem,
			private_key_pem=leaf_key_pem,
		)

		self.assertTrue(is_match)

	def test_validate_certificate_and_key_pair_detects_mismatch(self):
		ca_key_pem = services.create_private_key()
		ca_cert_pem = services.create_self_signed_ca(
			private_key_pem=ca_key_pem,
			subject={**self.subject, 'common_name': 'Example Root CA'},
			days_valid=3650,
		)

		leaf_key_pem = services.create_private_key()
		wrong_key_pem = services.create_private_key()

		csr_pem = services.create_csr(private_key_pem=leaf_key_pem, subject=self.subject)
		cert_pem = services.sign_certificate(
			csr_pem=csr_pem,
			ca_cert_pem=ca_cert_pem,
			ca_private_key_pem=ca_key_pem,
			days_valid=365,
		)

		is_match = services.validate_certificate_key_pair(
			certificate_pem=cert_pem,
			private_key_pem=wrong_key_pem,
		)

		self.assertFalse(is_match)

	def test_parse_certificate_info(self):
		ca_key_pem = services.create_private_key()
		ca_cert_pem = services.create_self_signed_ca(
			private_key_pem=ca_key_pem,
			subject={**self.subject, 'common_name': 'Parseable CA'},
			days_valid=3650,
		)

		info = services.parse_certificate_info(ca_cert_pem)
		self.assertEqual(info['subject']['common_name'], 'Parseable CA')
		self.assertIn('not_valid_after', info)

	def test_verify_certificate_signature(self):
		ca_key_pem = services.create_private_key()
		ca_cert_pem = services.create_self_signed_ca(
			private_key_pem=ca_key_pem,
			subject={**self.subject, 'common_name': 'Signer CA'},
			days_valid=3650,
		)
		leaf_key_pem = services.create_private_key()
		csr_pem = services.create_csr(private_key_pem=leaf_key_pem, subject=self.subject)
		cert_pem = services.sign_certificate(
			csr_pem=csr_pem,
			ca_cert_pem=ca_cert_pem,
			ca_private_key_pem=ca_key_pem,
			days_valid=365,
		)

		self.assertTrue(
			services.verify_certificate_signature(
				certificate_pem=cert_pem,
				issuer_certificate_pem=ca_cert_pem,
			)
		)

	def test_create_elliptic_curve_private_key(self):
		private_key_pem = services.create_private_key(key_algorithm='ec', curve_name='secp256r1')
		self.assertIn(b'BEGIN PRIVATE KEY', private_key_pem)

	def test_issue_certificate_with_elliptic_curve_keys(self):
		ca_key_pem = services.create_private_key(key_algorithm='ec', curve_name='secp384r1')
		ca_cert_pem = services.create_self_signed_ca(
			private_key_pem=ca_key_pem,
			subject={**self.subject, 'common_name': 'EC Root CA'},
			days_valid=3650,
		)

		leaf_key_pem = services.create_private_key(key_algorithm='ec', curve_name='secp256r1')
		csr_pem = services.create_csr(private_key_pem=leaf_key_pem, subject=self.subject)
		cert_pem = services.sign_certificate(
			csr_pem=csr_pem,
			ca_cert_pem=ca_cert_pem,
			ca_private_key_pem=ca_key_pem,
			days_valid=365,
		)

		self.assertTrue(
			services.validate_certificate_key_pair(
				certificate_pem=cert_pem,
				private_key_pem=leaf_key_pem,
			)
		)
		self.assertTrue(
			services.verify_certificate_signature(
				certificate_pem=cert_pem,
				issuer_certificate_pem=ca_cert_pem,
			)
		)

	def test_create_additional_recommended_ec_curves(self):
		for curve_name in ['secp256k1', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1']:
			private_key_pem = services.create_private_key(key_algorithm='ec', curve_name=curve_name)
			self.assertIn(b'BEGIN PRIVATE KEY', private_key_pem)

	def test_create_eddsa_private_keys(self):
		ed25519_key_pem = services.create_private_key(key_algorithm='eddsa', curve_name='ed25519')
		ed448_key_pem = services.create_private_key(key_algorithm='eddsa', curve_name='ed448')
		self.assertIn(b'BEGIN PRIVATE KEY', ed25519_key_pem)
		self.assertIn(b'BEGIN PRIVATE KEY', ed448_key_pem)

	def test_issue_certificate_with_ed25519_keys(self):
		ca_key_pem = services.create_private_key(key_algorithm='eddsa', curve_name='ed25519')
		ca_cert_pem = services.create_self_signed_ca(
			private_key_pem=ca_key_pem,
			subject={**self.subject, 'common_name': 'Ed25519 Root CA'},
			days_valid=3650,
		)

		leaf_key_pem = services.create_private_key(key_algorithm='eddsa', curve_name='ed25519')
		csr_pem = services.create_csr(private_key_pem=leaf_key_pem, subject=self.subject)
		cert_pem = services.sign_certificate(
			csr_pem=csr_pem,
			ca_cert_pem=ca_cert_pem,
			ca_private_key_pem=ca_key_pem,
			days_valid=365,
		)

		self.assertTrue(
			services.validate_certificate_key_pair(
				certificate_pem=cert_pem,
				private_key_pem=leaf_key_pem,
			)
		)
		self.assertTrue(
			services.verify_certificate_signature(
				certificate_pem=cert_pem,
				issuer_certificate_pem=ca_cert_pem,
			)
		)

	def test_create_x25519_and_x448_private_keys(self):
		x25519_key_pem = services.create_private_key(key_algorithm='x25519')
		x448_key_pem = services.create_private_key(key_algorithm='x448')
		self.assertIn(b'BEGIN PRIVATE KEY', x25519_key_pem)
		self.assertIn(b'BEGIN PRIVATE KEY', x448_key_pem)

	def test_derive_shared_secret_for_x25519(self):
		alice_private_key_pem = services.create_private_key(key_algorithm='x25519')
		bob_private_key_pem = services.create_private_key(key_algorithm='x25519')

		alice_public_key_pem = services.get_public_key_pem(alice_private_key_pem)
		bob_public_key_pem = services.get_public_key_pem(bob_private_key_pem)

		alice_secret = services.derive_shared_secret(
			private_key_pem=alice_private_key_pem,
			peer_public_key_pem=bob_public_key_pem,
		)
		bob_secret = services.derive_shared_secret(
			private_key_pem=bob_private_key_pem,
			peer_public_key_pem=alice_public_key_pem,
		)

		self.assertEqual(alice_secret, bob_secret)

	def test_derive_shared_secret_rejects_mismatched_curves(self):
		x25519_private_key_pem = services.create_private_key(key_algorithm='x25519')
		x448_private_key_pem = services.create_private_key(key_algorithm='x448')
		x448_public_key_pem = services.get_public_key_pem(x448_private_key_pem)

		with self.assertRaises(TypeError):
			services.derive_shared_secret(
				private_key_pem=x25519_private_key_pem,
				peer_public_key_pem=x448_public_key_pem,
			)
