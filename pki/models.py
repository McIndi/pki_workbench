from __future__ import annotations

from django.conf import settings
from django.db import models
from encrypted_fields.fields import EncryptedTextField


class PrivateKey(models.Model):
	class Algorithm(models.TextChoices):
		RSA = 'rsa', 'RSA'
		EC = 'ec', 'Elliptic Curve'
		EDDSA = 'eddsa', 'EdDSA'
		X25519 = 'x25519', 'X25519'
		X448 = 'x448', 'X448'

	name = models.CharField(max_length=150)
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='pki_private_keys',
		null=True,
		blank=True,
	)
	algorithm = models.CharField(max_length=20, choices=Algorithm.choices)
	curve_name = models.CharField(max_length=64, blank=True)
	key_size = models.PositiveIntegerField(null=True, blank=True)
	is_encrypted = models.BooleanField(default=False)
	private_key_pem = EncryptedTextField()
	created_at = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return self.name


class CertificateSigningRequest(models.Model):
	name = models.CharField(max_length=150)
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='pki_csrs',
		null=True,
		blank=True,
	)
	private_key = models.ForeignKey(PrivateKey, on_delete=models.PROTECT, related_name='csrs', null=True, blank=True)
	subject = models.JSONField(default=dict)
	csr_pem = models.TextField()
	created_at = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return self.name


class SignedCertificate(models.Model):
	name = models.CharField(max_length=150)
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='pki_certificates',
		null=True,
		blank=True,
	)
	certificate_pem = models.TextField()
	serial_number = models.CharField(max_length=128)
	not_valid_before = models.DateTimeField()
	not_valid_after = models.DateTimeField()
	issued_by = models.ForeignKey(
		'CertificateAuthority',
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='issued_certificates',
	)
	private_key = models.ForeignKey(PrivateKey, on_delete=models.PROTECT, related_name='certificates', null=True, blank=True)
	csr = models.ForeignKey(
		CertificateSigningRequest,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='signed_certificates',
	)
	created_at = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return self.name


class CertificateProfile(models.Model):
	name = models.CharField(max_length=150)
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='pki_certificate_profiles',
		null=True,
		blank=True,
	)
	description = models.TextField(blank=True)
	is_ca = models.BooleanField(default=False)
	path_length = models.PositiveSmallIntegerField(null=True, blank=True)
	days_valid = models.PositiveIntegerField(default=365)
	key_algorithm = models.CharField(max_length=20, default='rsa')
	curve_name = models.CharField(max_length=64, blank=True, default='secp256r1')
	key_size = models.PositiveIntegerField(null=True, blank=True, default=2048)
	public_exponent = models.PositiveIntegerField(default=65537)
	country_name = models.CharField(max_length=2, blank=True, default='')
	state_or_province_name = models.CharField(max_length=128, blank=True, default='')
	locality_name = models.CharField(max_length=128, blank=True, default='')
	organization_name = models.CharField(max_length=255, blank=True, default='')
	organizational_unit_name = models.CharField(max_length=255, blank=True, default='')
	common_name = models.CharField(max_length=255, blank=True, default='')
	email_address = models.EmailField(blank=True, default='')

	ku_digital_signature = models.BooleanField(default=True)
	ku_content_commitment = models.BooleanField(default=False)
	ku_key_encipherment = models.BooleanField(default=True)
	ku_data_encipherment = models.BooleanField(default=False)
	ku_key_agreement = models.BooleanField(default=False)
	ku_key_cert_sign = models.BooleanField(default=False)
	ku_crl_sign = models.BooleanField(default=False)
	ku_encipher_only = models.BooleanField(default=False)
	ku_decipher_only = models.BooleanField(default=False)
	ku_critical = models.BooleanField(default=True)

	eku_server_auth = models.BooleanField(default=True)
	eku_client_auth = models.BooleanField(default=False)
	eku_code_signing = models.BooleanField(default=False)
	eku_email_protection = models.BooleanField(default=False)
	eku_time_stamping = models.BooleanField(default=False)
	eku_ocsp_signing = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['owner', 'name'], name='unique_profile_name_per_owner'),
		]

	def key_usage_payload(self) -> dict:
		return {
			'digital_signature': self.ku_digital_signature,
			'content_commitment': self.ku_content_commitment,
			'key_encipherment': self.ku_key_encipherment,
			'data_encipherment': self.ku_data_encipherment,
			'key_agreement': self.ku_key_agreement,
			'key_cert_sign': self.ku_key_cert_sign,
			'crl_sign': self.ku_crl_sign,
			'encipher_only': self.ku_encipher_only,
			'decipher_only': self.ku_decipher_only,
			'critical': self.ku_critical,
		}

	def extended_key_usage_payload(self) -> list[str]:
		payload = []
		if self.eku_server_auth:
			payload.append('server_auth')
		if self.eku_client_auth:
			payload.append('client_auth')
		if self.eku_code_signing:
			payload.append('code_signing')
		if self.eku_email_protection:
			payload.append('email_protection')
		if self.eku_time_stamping:
			payload.append('time_stamping')
		if self.eku_ocsp_signing:
			payload.append('ocsp_signing')
		return payload

	def subject_payload(self) -> dict:
		payload = {}
		if self.country_name:
			payload['country_name'] = self.country_name
		if self.state_or_province_name:
			payload['state_or_province_name'] = self.state_or_province_name
		if self.locality_name:
			payload['locality_name'] = self.locality_name
		if self.organization_name:
			payload['organization_name'] = self.organization_name
		if self.organizational_unit_name:
			payload['organizational_unit_name'] = self.organizational_unit_name
		if self.common_name:
			payload['common_name'] = self.common_name
		if self.email_address:
			payload['email_address'] = self.email_address
		return payload

	def __str__(self):
		return self.name


class CertificateAuthority(models.Model):
	name = models.CharField(max_length=150)
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='pki_certificate_authorities',
		null=True,
		blank=True,
	)
	parent = models.ForeignKey(
		'self',
		on_delete=models.PROTECT,
		null=True,
		blank=True,
		related_name='children',
	)
	depth = models.PositiveSmallIntegerField(default=0)
	certification_depth = models.PositiveSmallIntegerField(default=3)
	private_key = models.OneToOneField(PrivateKey, on_delete=models.PROTECT, related_name='certificate_authority')
	certificate = models.OneToOneField(SignedCertificate, on_delete=models.PROTECT, related_name='certificate_authority')
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['owner', 'name'], name='unique_ca_name_per_owner'),
		]

	@property
	def is_root(self) -> bool:
		return self.parent is None

	@property
	def root(self) -> CertificateAuthority:
		node = self
		while node.parent is not None:
			node = node.parent
		return node

	def __str__(self):
		return self.name
