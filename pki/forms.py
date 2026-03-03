from django import forms

from .models import CertificateAuthority, CertificateProfile, PrivateKey


KEY_ALGORITHM_CHOICES = [
    (PrivateKey.Algorithm.RSA, 'RSA'),
    (PrivateKey.Algorithm.EC, 'Elliptic Curve'),
    (PrivateKey.Algorithm.EDDSA, 'EdDSA'),
]

EC_CURVE_CHOICES = [
    ('secp256r1', 'secp256r1'),
    ('secp384r1', 'secp384r1'),
    ('secp521r1', 'secp521r1'),
    ('brainpoolP256r1', 'brainpoolP256r1'),
    ('brainpoolP384r1', 'brainpoolP384r1'),
    ('brainpoolP512r1', 'brainpoolP512r1'),
    ('secp256k1', 'secp256k1'),
]

EDDSA_CURVE_CHOICES = [
    ('ed25519', 'ed25519'),
    ('ed448', 'ed448'),
]

ALL_CURVE_CHOICES = EC_CURVE_CHOICES + EDDSA_CURVE_CHOICES

COUNTRY_CHOICES = [
    ('US', 'US'),
    ('CA', 'CA'),
    ('GB', 'GB'),
    ('DE', 'DE'),
    ('FR', 'FR'),
    ('IN', 'IN'),
]


class BasePKIForm(forms.Form):
    def subject_payload(self):
        cleaned = self.cleaned_data
        payload = {
            'country_name': cleaned['country_name'],
            'state_or_province_name': cleaned['state_or_province_name'],
            'locality_name': cleaned['locality_name'],
            'organization_name': cleaned['organization_name'],
            'common_name': cleaned['common_name'],
        }
        if cleaned.get('organizational_unit_name'):
            payload['organizational_unit_name'] = cleaned['organizational_unit_name']
        if cleaned.get('email_address'):
            payload['email_address'] = cleaned['email_address']
        return payload

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.update({'class': 'form-check-input'})
            else:
                field.widget.attrs.update({'class': 'form-control'})
            if field_name in {'key_algorithm', 'curve_name', 'country_name'}:
                field.widget.attrs.update({'class': 'form-select'})


class RootCAForm(BasePKIForm):
    name = forms.CharField(max_length=150)
    country_name = forms.ChoiceField(choices=COUNTRY_CHOICES, initial='US')
    state_or_province_name = forms.CharField(max_length=128)
    locality_name = forms.CharField(max_length=128)
    organization_name = forms.CharField(max_length=255)
    common_name = forms.CharField(max_length=255)
    email_address = forms.EmailField(required=False)
    certification_depth = forms.IntegerField(min_value=1, max_value=10, initial=3)
    days_valid = forms.IntegerField(min_value=1, initial=3650)
    key_algorithm = forms.ChoiceField(choices=KEY_ALGORITHM_CHOICES, initial=PrivateKey.Algorithm.RSA)
    curve_name = forms.ChoiceField(choices=ALL_CURVE_CHOICES, required=False, initial='secp256r1')
    key_size = forms.IntegerField(required=False, min_value=2048, initial=2048)
    public_exponent = forms.IntegerField(required=False, initial=65537)
    passphrase = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))

    def clean(self):
        cleaned = super().clean()
        algorithm = cleaned.get('key_algorithm')
        curve_name = cleaned.get('curve_name')

        if algorithm == PrivateKey.Algorithm.RSA:
            if not cleaned.get('key_size'):
                self.add_error('key_size', 'Key size is required for RSA.')
            if not cleaned.get('public_exponent'):
                cleaned['public_exponent'] = 65537
        elif algorithm == PrivateKey.Algorithm.EC:
            if not curve_name:
                self.add_error('curve_name', 'Curve is required for EC keys.')
        elif algorithm == PrivateKey.Algorithm.EDDSA:
            if curve_name not in {'ed25519', 'ed448'}:
                self.add_error('curve_name', 'Choose ed25519 or ed448 for EdDSA keys.')
        return cleaned


class IntermediateCAForm(BasePKIForm):
    name = forms.CharField(max_length=150)
    country_name = forms.ChoiceField(choices=COUNTRY_CHOICES, initial='US')
    state_or_province_name = forms.CharField(max_length=128)
    locality_name = forms.CharField(max_length=128)
    organization_name = forms.CharField(max_length=255)
    common_name = forms.CharField(max_length=255)
    email_address = forms.EmailField(required=False)
    days_valid = forms.IntegerField(min_value=1, initial=1825)
    key_algorithm = forms.ChoiceField(choices=KEY_ALGORITHM_CHOICES, initial=PrivateKey.Algorithm.RSA)
    curve_name = forms.ChoiceField(choices=ALL_CURVE_CHOICES, required=False, initial='secp256r1')
    key_size = forms.IntegerField(required=False, min_value=2048, initial=2048)
    public_exponent = forms.IntegerField(required=False, initial=65537)
    passphrase = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))
    parent_key_passphrase = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))

    def clean(self):
        cleaned = super().clean()
        algorithm = cleaned.get('key_algorithm')
        curve_name = cleaned.get('curve_name')

        if algorithm == PrivateKey.Algorithm.RSA and not cleaned.get('key_size'):
            self.add_error('key_size', 'Key size is required for RSA.')
        if algorithm == PrivateKey.Algorithm.EC and not curve_name:
            self.add_error('curve_name', 'Curve is required for EC keys.')
        if algorithm == PrivateKey.Algorithm.EDDSA and curve_name not in {'ed25519', 'ed448'}:
            self.add_error('curve_name', 'Choose ed25519 or ed448 for EdDSA keys.')
        return cleaned


class IssueCertificateForm(BasePKIForm):
    certificate_profile = forms.ModelChoiceField(
        queryset=CertificateProfile.objects.none(),
        required=False,
        empty_label='Custom settings (no profile)',
    )
    name = forms.CharField(max_length=150, help_text='Friendly name for the issued certificate record')
    country_name = forms.ChoiceField(choices=COUNTRY_CHOICES, initial='US')
    state_or_province_name = forms.CharField(max_length=128)
    locality_name = forms.CharField(max_length=128)
    organization_name = forms.CharField(max_length=255)
    organizational_unit_name = forms.CharField(max_length=255, required=False)
    common_name = forms.CharField(max_length=255)
    email_address = forms.EmailField(required=False)
    days_valid = forms.IntegerField(min_value=1, initial=365)
    key_algorithm = forms.ChoiceField(choices=KEY_ALGORITHM_CHOICES, initial=PrivateKey.Algorithm.RSA)
    curve_name = forms.ChoiceField(choices=ALL_CURVE_CHOICES, required=False, initial='secp256r1')
    key_size = forms.IntegerField(required=False, min_value=2048, initial=2048)
    public_exponent = forms.IntegerField(required=False, initial=65537)
    passphrase = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))
    issuer_key_passphrase = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))
    san_dns_names = forms.CharField(required=False, help_text='Comma-separated DNS names')

    ku_digital_signature = forms.BooleanField(required=False, initial=True)
    ku_content_commitment = forms.BooleanField(required=False, initial=False)
    ku_key_encipherment = forms.BooleanField(required=False, initial=True)
    ku_data_encipherment = forms.BooleanField(required=False, initial=False)
    ku_key_agreement = forms.BooleanField(required=False, initial=False)
    ku_key_cert_sign = forms.BooleanField(required=False, initial=False)
    ku_crl_sign = forms.BooleanField(required=False, initial=False)
    ku_encipher_only = forms.BooleanField(required=False, initial=False)
    ku_decipher_only = forms.BooleanField(required=False, initial=False)
    ku_critical = forms.BooleanField(required=False, initial=True)

    eku_server_auth = forms.BooleanField(required=False, initial=True)
    eku_client_auth = forms.BooleanField(required=False, initial=False)
    eku_code_signing = forms.BooleanField(required=False, initial=False)
    eku_email_protection = forms.BooleanField(required=False, initial=False)
    eku_time_stamping = forms.BooleanField(required=False, initial=False)
    eku_ocsp_signing = forms.BooleanField(required=False, initial=False)

    def __init__(self, *args, profile_queryset=None, **kwargs):
        super().__init__(*args, **kwargs)
        if profile_queryset is None:
            profile_queryset = CertificateProfile.objects.none()
        self.fields['certificate_profile'].queryset = profile_queryset

    def clean(self):
        cleaned = super().clean()
        algorithm = cleaned.get('key_algorithm')
        curve_name = cleaned.get('curve_name')

        if algorithm == PrivateKey.Algorithm.RSA and not cleaned.get('key_size'):
            self.add_error('key_size', 'Key size is required for RSA.')
        if algorithm == PrivateKey.Algorithm.EC and not curve_name:
            self.add_error('curve_name', 'Curve is required for EC keys.')
        if algorithm == PrivateKey.Algorithm.EDDSA and curve_name not in {'ed25519', 'ed448'}:
            self.add_error('curve_name', 'Choose ed25519 or ed448 for EdDSA keys.')
        return cleaned

    def san_dns_name_list(self):
        raw = self.cleaned_data.get('san_dns_names', '')
        if not raw:
            return []
        return [item.strip() for item in raw.split(',') if item.strip()]

    def key_usage_payload(self) -> dict:
        return {
            'digital_signature': self.cleaned_data['ku_digital_signature'],
            'content_commitment': self.cleaned_data['ku_content_commitment'],
            'key_encipherment': self.cleaned_data['ku_key_encipherment'],
            'data_encipherment': self.cleaned_data['ku_data_encipherment'],
            'key_agreement': self.cleaned_data['ku_key_agreement'],
            'key_cert_sign': self.cleaned_data['ku_key_cert_sign'],
            'crl_sign': self.cleaned_data['ku_crl_sign'],
            'encipher_only': self.cleaned_data['ku_encipher_only'],
            'decipher_only': self.cleaned_data['ku_decipher_only'],
            'critical': self.cleaned_data['ku_critical'],
        }

    def extended_key_usage_payload(self) -> list[str]:
        payload = []
        if self.cleaned_data['eku_server_auth']:
            payload.append('server_auth')
        if self.cleaned_data['eku_client_auth']:
            payload.append('client_auth')
        if self.cleaned_data['eku_code_signing']:
            payload.append('code_signing')
        if self.cleaned_data['eku_email_protection']:
            payload.append('email_protection')
        if self.cleaned_data['eku_time_stamping']:
            payload.append('time_stamping')
        if self.cleaned_data['eku_ocsp_signing']:
            payload.append('ocsp_signing')
        return payload


class CertificateProfileForm(BasePKIForm, forms.ModelForm):
    key_algorithm = forms.ChoiceField(choices=KEY_ALGORITHM_CHOICES, initial=PrivateKey.Algorithm.RSA)
    curve_name = forms.ChoiceField(choices=ALL_CURVE_CHOICES, required=False, initial='secp256r1')
    country_name = forms.ChoiceField(choices=[('', 'Any country'), *COUNTRY_CHOICES], required=False)

    class Meta:
        model = CertificateProfile
        fields = [
            'name',
            'description',
            'is_ca',
            'path_length',
            'days_valid',
            'key_algorithm',
            'curve_name',
            'key_size',
            'public_exponent',
            'country_name',
            'state_or_province_name',
            'locality_name',
            'organization_name',
            'organizational_unit_name',
            'common_name',
            'email_address',
            'ku_digital_signature',
            'ku_content_commitment',
            'ku_key_encipherment',
            'ku_data_encipherment',
            'ku_key_agreement',
            'ku_key_cert_sign',
            'ku_crl_sign',
            'ku_encipher_only',
            'ku_decipher_only',
            'ku_critical',
            'eku_server_auth',
            'eku_client_auth',
            'eku_code_signing',
            'eku_email_protection',
            'eku_time_stamping',
            'eku_ocsp_signing',
        ]

    def clean(self):
        cleaned = super().clean()
        algorithm = cleaned.get('key_algorithm')
        curve_name = cleaned.get('curve_name')

        if algorithm == PrivateKey.Algorithm.RSA and not cleaned.get('key_size'):
            self.add_error('key_size', 'Key size is required for RSA profiles.')
        if algorithm == PrivateKey.Algorithm.EC and not curve_name:
            self.add_error('curve_name', 'Curve is required for EC profiles.')
        if algorithm == PrivateKey.Algorithm.EDDSA and curve_name not in {'ed25519', 'ed448'}:
            self.add_error('curve_name', 'Choose ed25519 or ed448 for EdDSA profiles.')
        if cleaned.get('is_ca') and cleaned.get('path_length') is None:
            cleaned['path_length'] = 0
        if not cleaned.get('is_ca'):
            cleaned['path_length'] = None
        return cleaned


class CreateProfileFromCertificateForm(forms.Form):
    name = forms.CharField(max_length=150)
    description = forms.CharField(required=False, widget=forms.Textarea(attrs={'rows': 3}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.update({'class': 'form-control'})


class ImportCAForm(forms.Form):
    name = forms.CharField(max_length=150)
    certificate_pem = forms.CharField(widget=forms.Textarea(attrs={'rows': 8}), help_text='PEM-encoded CA certificate')
    private_key_pem = forms.CharField(widget=forms.Textarea(attrs={'rows': 8}), help_text='PEM-encoded matching private key')
    key_passphrase = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))
    parent_ca = forms.ModelChoiceField(queryset=CertificateAuthority.objects.none(), required=False)
    certification_depth = forms.IntegerField(min_value=1, max_value=10, initial=3)

    def __init__(self, *args, owner=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['parent_ca'].queryset = CertificateAuthority.objects.filter(owner=owner).order_by('name') if owner else CertificateAuthority.objects.none()
        for field_name, field in self.fields.items():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.update({'class': 'form-check-input'})
            else:
                field.widget.attrs.update({'class': 'form-control'})


class SignCSRForm(forms.Form):
    certificate_profile = forms.ModelChoiceField(
        queryset=CertificateProfile.objects.none(),
        required=False,
        empty_label='Custom settings (no profile)',
    )
    name = forms.CharField(max_length=150)
    csr_pem = forms.CharField(widget=forms.Textarea(attrs={'rows': 8}), help_text='PEM-encoded CSR')
    issuer_key_passphrase = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False))
    days_valid = forms.IntegerField(min_value=1, initial=365)

    ku_digital_signature = forms.BooleanField(required=False, initial=True)
    ku_content_commitment = forms.BooleanField(required=False, initial=False)
    ku_key_encipherment = forms.BooleanField(required=False, initial=True)
    ku_data_encipherment = forms.BooleanField(required=False, initial=False)
    ku_key_agreement = forms.BooleanField(required=False, initial=False)
    ku_key_cert_sign = forms.BooleanField(required=False, initial=False)
    ku_crl_sign = forms.BooleanField(required=False, initial=False)
    ku_encipher_only = forms.BooleanField(required=False, initial=False)
    ku_decipher_only = forms.BooleanField(required=False, initial=False)
    ku_critical = forms.BooleanField(required=False, initial=True)

    eku_server_auth = forms.BooleanField(required=False, initial=True)
    eku_client_auth = forms.BooleanField(required=False, initial=False)
    eku_code_signing = forms.BooleanField(required=False, initial=False)
    eku_email_protection = forms.BooleanField(required=False, initial=False)
    eku_time_stamping = forms.BooleanField(required=False, initial=False)
    eku_ocsp_signing = forms.BooleanField(required=False, initial=False)

    def __init__(self, *args, profile_queryset=None, **kwargs):
        super().__init__(*args, **kwargs)
        if profile_queryset is None:
            profile_queryset = CertificateProfile.objects.none()
        self.fields['certificate_profile'].queryset = profile_queryset
        for field in self.fields.values():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.update({'class': 'form-check-input'})
            else:
                field.widget.attrs.update({'class': 'form-control'})

    def key_usage_payload(self) -> dict:
        return {
            'digital_signature': self.cleaned_data['ku_digital_signature'],
            'content_commitment': self.cleaned_data['ku_content_commitment'],
            'key_encipherment': self.cleaned_data['ku_key_encipherment'],
            'data_encipherment': self.cleaned_data['ku_data_encipherment'],
            'key_agreement': self.cleaned_data['ku_key_agreement'],
            'key_cert_sign': self.cleaned_data['ku_key_cert_sign'],
            'crl_sign': self.cleaned_data['ku_crl_sign'],
            'encipher_only': self.cleaned_data['ku_encipher_only'],
            'decipher_only': self.cleaned_data['ku_decipher_only'],
            'critical': self.cleaned_data['ku_critical'],
        }

    def extended_key_usage_payload(self) -> list[str]:
        payload = []
        if self.cleaned_data['eku_server_auth']:
            payload.append('server_auth')
        if self.cleaned_data['eku_client_auth']:
            payload.append('client_auth')
        if self.cleaned_data['eku_code_signing']:
            payload.append('code_signing')
        if self.cleaned_data['eku_email_protection']:
            payload.append('email_protection')
        if self.cleaned_data['eku_time_stamping']:
            payload.append('time_stamping')
        if self.cleaned_data['eku_ocsp_signing']:
            payload.append('ocsp_signing')
        return payload
