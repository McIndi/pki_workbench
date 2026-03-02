import io
import zipfile

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.text import slugify
from django.views import View

from .forms import CertificateProfileForm, CreateProfileFromCertificateForm, IntermediateCAForm, IssueCertificateForm, RootCAForm
from .models import CertificateAuthority, CertificateProfile, SignedCertificate
from .workflows import (
	create_certificate_profile_from_certificate,
	create_intermediate_certificate_authority,
	create_root_certificate_authority,
	issue_signed_certificate,
)


class RootCACreateView(LoginRequiredMixin, View):
	template_name = 'pki/create_root_ca.html'

	def get(self, request: HttpRequest) -> HttpResponse:
		form = RootCAForm()
		return render(request, self.template_name, {'form': form})

	def post(self, request: HttpRequest) -> HttpResponse:
		form = RootCAForm(request.POST)
		if not form.is_valid():
			return render(request, self.template_name, {'form': form})

		try:
			root_ca = create_root_certificate_authority(
				owner=request.user,
				name=form.cleaned_data['name'],
				subject=form.subject_payload(),
				certification_depth=form.cleaned_data['certification_depth'],
				key_algorithm=form.cleaned_data['key_algorithm'],
				curve_name=form.cleaned_data.get('curve_name') or 'secp256r1',
				key_size=form.cleaned_data.get('key_size') or 2048,
				public_exponent=form.cleaned_data.get('public_exponent') or 65537,
				passphrase=form.cleaned_data.get('passphrase') or None,
				days_valid=form.cleaned_data['days_valid'],
			)
		except ValidationError as exc:
			form.add_error(None, exc.message)
			return render(request, self.template_name, {'form': form})

		messages.success(request, f'Root certificate authority "{root_ca.name}" created.')
		return redirect('pki-ca-workbench', ca_id=root_ca.id)


class CAWorkbenchView(LoginRequiredMixin, View):
	template_name = 'pki/ca_workbench.html'

	def _profile_queryset(self, request: HttpRequest):
		return CertificateProfile.objects.filter(owner__in=[None, request.user]).order_by('owner_id', 'name')

	def _get_ca(self, request: HttpRequest, ca_id: int) -> CertificateAuthority:
		try:
			return CertificateAuthority.objects.select_related('parent', 'private_key', 'certificate').get(
				id=ca_id,
				owner=request.user,
			)
		except CertificateAuthority.DoesNotExist as exc:
			raise Http404('Certificate authority not found.') from exc

	def get(self, request: HttpRequest, ca_id: int) -> HttpResponse:
		ca = self._get_ca(request, ca_id)
		context = self._build_context(ca, active_tab='issue')
		return render(request, self.template_name, context)

	def post(self, request: HttpRequest, ca_id: int) -> HttpResponse:
		ca = self._get_ca(request, ca_id)
		action = request.POST.get('action')

		intermediate_form = IntermediateCAForm(prefix='intermediate')
		issue_form = IssueCertificateForm(prefix='issue', profile_queryset=self._profile_queryset(request))
		profile_form = CertificateProfileForm(prefix='profile')
		active_tab = 'issue'

		if action == 'create_intermediate':
			active_tab = 'intermediate'
			intermediate_form = IntermediateCAForm(request.POST, prefix='intermediate')
			if intermediate_form.is_valid():
				try:
					child_ca = create_intermediate_certificate_authority(
						owner=request.user,
						parent_authority=ca,
						name=intermediate_form.cleaned_data['name'],
						subject=intermediate_form.subject_payload(),
						key_algorithm=intermediate_form.cleaned_data['key_algorithm'],
						curve_name=intermediate_form.cleaned_data.get('curve_name') or 'secp256r1',
						key_size=intermediate_form.cleaned_data.get('key_size') or 2048,
						public_exponent=intermediate_form.cleaned_data.get('public_exponent') or 65537,
						passphrase=intermediate_form.cleaned_data.get('passphrase') or None,
						parent_key_passphrase=intermediate_form.cleaned_data.get('parent_key_passphrase') or None,
						days_valid=intermediate_form.cleaned_data['days_valid'],
					)
				except ValidationError as exc:
					intermediate_form.add_error(None, exc.message)
				else:
					messages.success(request, f'Intermediate CA "{child_ca.name}" created.')
					return redirect('pki-ca-workbench', ca_id=ca.id)

		elif action == 'issue_certificate':
			active_tab = 'issue'
			issue_form = IssueCertificateForm(
				request.POST,
				prefix='issue',
				profile_queryset=self._profile_queryset(request),
			)
			if issue_form.is_valid():
				try:
					signed_certificate = issue_signed_certificate(
						owner=request.user,
						issuer_authority=ca,
						name=issue_form.cleaned_data['name'],
						subject=issue_form.subject_payload(),
						key_algorithm=issue_form.cleaned_data['key_algorithm'],
						curve_name=issue_form.cleaned_data.get('curve_name') or 'secp256r1',
						key_size=issue_form.cleaned_data.get('key_size') or 2048,
						public_exponent=issue_form.cleaned_data.get('public_exponent') or 65537,
						certificate_profile=issue_form.cleaned_data.get('certificate_profile'),
						passphrase=issue_form.cleaned_data.get('passphrase') or None,
						issuer_key_passphrase=issue_form.cleaned_data.get('issuer_key_passphrase') or None,
						days_valid=issue_form.cleaned_data['days_valid'],
						san_dns_names=issue_form.san_dns_name_list(),
						key_usage=issue_form.key_usage_payload(),
						extended_key_usages=issue_form.extended_key_usage_payload(),
					)
				except ValidationError as exc:
					issue_form.add_error(None, exc.message)
				else:
					messages.success(request, f'Certificate "{signed_certificate.name}" issued.')
					return redirect('pki-ca-workbench', ca_id=ca.id)

		elif action == 'create_certificate_profile':
			active_tab = 'profile'
			profile_form = CertificateProfileForm(request.POST, prefix='profile')
			if profile_form.is_valid():
				try:
					profile = profile_form.save(commit=False)
					profile.owner = request.user
					profile.save()
				except Exception as exc:
					profile_form.add_error(None, str(exc))
				else:
					messages.success(request, f'Certificate profile "{profile.name}" created.')
					return redirect('pki-ca-workbench', ca_id=ca.id)

		context = self._build_context(
			ca,
			intermediate_form=intermediate_form,
			issue_form=issue_form,
			profile_form=profile_form,
			active_tab=active_tab,
		)
		return render(request, self.template_name, context)

	def _build_context(
		self,
		ca: CertificateAuthority,
		*,
		intermediate_form: IntermediateCAForm | None = None,
		issue_form: IssueCertificateForm | None = None,
		profile_form: CertificateProfileForm | None = None,
		active_tab: str = 'issue',
	) -> dict:
		resolved_issue_form = issue_form or IssueCertificateForm(
			prefix='issue',
			profile_queryset=CertificateProfile.objects.filter(owner__in=[None, ca.owner]).order_by('owner_id', 'name'),
		)

		issue_profiles = resolved_issue_form.fields['certificate_profile'].queryset
		issue_profile_payload = {
			str(profile.id): {
				'key_algorithm': profile.key_algorithm,
				'curve_name': profile.curve_name,
				'key_size': profile.key_size,
				'public_exponent': profile.public_exponent,
				'days_valid': profile.days_valid,
				'country_name': profile.country_name,
				'state_or_province_name': profile.state_or_province_name,
				'locality_name': profile.locality_name,
				'organization_name': profile.organization_name,
				'organizational_unit_name': profile.organizational_unit_name,
				'common_name': profile.common_name,
				'email_address': profile.email_address,
				'ku_digital_signature': profile.ku_digital_signature,
				'ku_content_commitment': profile.ku_content_commitment,
				'ku_key_encipherment': profile.ku_key_encipherment,
				'ku_data_encipherment': profile.ku_data_encipherment,
				'ku_key_agreement': profile.ku_key_agreement,
				'ku_key_cert_sign': profile.ku_key_cert_sign,
				'ku_crl_sign': profile.ku_crl_sign,
				'ku_encipher_only': profile.ku_encipher_only,
				'ku_decipher_only': profile.ku_decipher_only,
				'ku_critical': profile.ku_critical,
				'eku_server_auth': profile.eku_server_auth,
				'eku_client_auth': profile.eku_client_auth,
				'eku_code_signing': profile.eku_code_signing,
				'eku_email_protection': profile.eku_email_protection,
				'eku_time_stamping': profile.eku_time_stamping,
				'eku_ocsp_signing': profile.eku_ocsp_signing,
			}
			for profile in issue_profiles
		}

		children = ca.children.select_related('certificate').all().order_by('name')
		issued_certificates = ca.issued_certificates.select_related('private_key').all().order_by('-created_at')
		chain = []
		node = ca
		while node is not None:
			chain.append(node)
			node = node.parent
		chain.reverse()

		all_cas = CertificateAuthority.objects.filter(owner=ca.owner).order_by('depth', 'name')
		editable_profiles = CertificateProfile.objects.filter(owner=ca.owner).order_by('name')

		return {
			'ca': ca,
			'chain': chain,
			'children': children,
			'issued_certificates': issued_certificates,
			'all_cas': all_cas,
			'editable_profiles': editable_profiles,
			'intermediate_form': intermediate_form or IntermediateCAForm(prefix='intermediate'),
			'issue_form': resolved_issue_form,
			'profile_form': profile_form or CertificateProfileForm(prefix='profile'),
			'active_tab': active_tab,
			'issue_profile_payload': issue_profile_payload,
		}


class CertificateProfileUpdateView(LoginRequiredMixin, View):
	template_name = 'pki/edit_certificate_profile.html'

	def _get_profile(self, request: HttpRequest, profile_id: int) -> CertificateProfile:
		try:
			return CertificateProfile.objects.get(id=profile_id, owner=request.user)
		except CertificateProfile.DoesNotExist as exc:
			raise Http404('Certificate profile not found.') from exc

	def _workbench_redirect(self, request: HttpRequest, profile: CertificateProfile) -> HttpResponse:
		ca_id = request.POST.get('ca_id') or request.GET.get('ca_id')
		if ca_id:
			try:
				authority = CertificateAuthority.objects.get(id=ca_id, owner=request.user)
			except CertificateAuthority.DoesNotExist:
				pass
			else:
				return redirect('pki-ca-workbench', ca_id=authority.id)

		first_ca = request.user.pki_certificate_authorities.order_by('depth', 'name').first()
		if first_ca is not None:
			return redirect('pki-ca-workbench', ca_id=first_ca.id)
		return redirect('pki-create-root-ca')

	def get(self, request: HttpRequest, profile_id: int) -> HttpResponse:
		profile = self._get_profile(request, profile_id)
		form = CertificateProfileForm(prefix='profile', instance=profile)
		return render(
			request,
			self.template_name,
			{
				'profile': profile,
				'form': form,
				'ca_id': request.GET.get('ca_id', ''),
			},
		)

	def post(self, request: HttpRequest, profile_id: int) -> HttpResponse:
		profile = self._get_profile(request, profile_id)
		form = CertificateProfileForm(request.POST, prefix='profile', instance=profile)
		if not form.is_valid():
			return render(
				request,
				self.template_name,
				{
					'profile': profile,
					'form': form,
					'ca_id': request.POST.get('ca_id', ''),
				},
			)

		updated_profile = form.save()
		messages.success(request, f'Certificate profile "{updated_profile.name}" updated.')
		return self._workbench_redirect(request, updated_profile)


def _artifact_basename(certificate: SignedCertificate) -> str:
	return slugify(certificate.name) or f'certificate-{certificate.pk}'


def _filename_for_artifact(certificate: SignedCertificate, artifact: str, extension: str) -> str:
	base = _artifact_basename(certificate)
	return f'{base}_{artifact}.{extension}'


def _certificate_chain_pem(certificate: SignedCertificate) -> str:
	chain = [certificate.certificate_pem.strip()]
	issuer = certificate.issued_by
	while issuer is not None:
		chain.append(issuer.certificate.certificate_pem.strip())
		issuer = issuer.parent
	return '\n'.join(chain) + '\n'


class IssuedCertificateDetailView(LoginRequiredMixin, View):
	template_name = 'pki/issued_certificate_detail.html'

	def _get_certificate(self, request: HttpRequest, certificate_id: int) -> SignedCertificate:
		try:
			return SignedCertificate.objects.select_related('issued_by', 'issued_by__parent', 'private_key', 'csr').get(
				id=certificate_id,
				owner=request.user,
			)
		except SignedCertificate.DoesNotExist as exc:
			raise Http404('Issued certificate not found.') from exc

	def get(self, request: HttpRequest, certificate_id: int) -> HttpResponse:
		certificate = self._get_certificate(request, certificate_id)
		profile_from_certificate_form = CreateProfileFromCertificateForm(
			prefix='from-cert',
			initial={'name': f'{certificate.name} Profile'},
		)
		return render(
			request,
			self.template_name,
			{'certificate': certificate, 'profile_from_certificate_form': profile_from_certificate_form},
		)

	def post(self, request: HttpRequest, certificate_id: int) -> HttpResponse:
		certificate = self._get_certificate(request, certificate_id)
		profile_from_certificate_form = CreateProfileFromCertificateForm(request.POST, prefix='from-cert')

		if profile_from_certificate_form.is_valid():
			try:
				profile = create_certificate_profile_from_certificate(
					owner=request.user,
					certificate=certificate,
					name=profile_from_certificate_form.cleaned_data['name'],
					description=profile_from_certificate_form.cleaned_data.get('description') or '',
				)
			except ValidationError as exc:
				profile_from_certificate_form.add_error(None, exc.message)
			else:
				messages.success(request, f'Certificate profile "{profile.name}" created from certificate.')
				if certificate.issued_by:
					return redirect('pki-ca-workbench', ca_id=certificate.issued_by.id)
				return redirect('pki-issued-certificate-detail', certificate_id=certificate.id)

		return render(
			request,
			self.template_name,
			{'certificate': certificate, 'profile_from_certificate_form': profile_from_certificate_form},
		)


class IssuedCertificateDownloadView(LoginRequiredMixin, View):
	def _get_certificate(self, request: HttpRequest, certificate_id: int) -> SignedCertificate:
		try:
			return SignedCertificate.objects.select_related('issued_by', 'issued_by__parent', 'private_key', 'csr').get(
				id=certificate_id,
				owner=request.user,
			)
		except SignedCertificate.DoesNotExist as exc:
			raise Http404('Issued certificate not found.') from exc

	def get(self, request: HttpRequest, certificate_id: int, artifact: str) -> HttpResponse:
		certificate = self._get_certificate(request, certificate_id)

		if artifact == 'pubcert':
			response = HttpResponse(certificate.certificate_pem, content_type='application/x-pem-file')
			response['Content-Disposition'] = (
				f'attachment; filename="{_filename_for_artifact(certificate, "pubcert", "pem")}"'
			)
			return response

		if artifact == 'pubcert-chain':
			response = HttpResponse(_certificate_chain_pem(certificate), content_type='application/x-pem-file')
			response['Content-Disposition'] = (
				f'attachment; filename="{_filename_for_artifact(certificate, "pubcert-chain", "pem")}"'
			)
			return response

		if artifact == 'csr':
			if certificate.csr is None:
				raise Http404('CSR is not available for this certificate.')
			response = HttpResponse(certificate.csr.csr_pem, content_type='application/x-pem-file')
			response['Content-Disposition'] = (
				f'attachment; filename="{_filename_for_artifact(certificate, "csr", "pem")}"'
			)
			return response

		if artifact == 'pair-zip':
			archive_bytes = io.BytesIO()
			with zipfile.ZipFile(archive_bytes, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
				archive.writestr(_filename_for_artifact(certificate, 'pubcert', 'pem'), certificate.certificate_pem)
				archive.writestr(_filename_for_artifact(certificate, 'privkey', 'pem'), certificate.private_key.private_key_pem)
				if certificate.csr is not None:
					archive.writestr(_filename_for_artifact(certificate, 'csr', 'pem'), certificate.csr.csr_pem)
			response = HttpResponse(archive_bytes.getvalue(), content_type='application/zip')
			response['Content-Disposition'] = (
				f'attachment; filename="{_filename_for_artifact(certificate, "pubcert-privkey-pair", "zip")}"'
			)
			return response

		raise Http404('Unknown download artifact.')
