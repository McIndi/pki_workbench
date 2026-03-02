const EC_CURVES = [
  'secp256r1',
  'secp384r1',
  'secp521r1',
  'brainpoolP256r1',
  'brainpoolP384r1',
  'brainpoolP512r1',
  'secp256k1',
];

const EDDSA_CURVES = ['ed25519', 'ed448'];

const PROFILE_BOUND_FIELD_SUFFIXES = [
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
];

const OPTIONAL_SUBJECT_FIELD_SUFFIXES = new Set([
  'country_name',
  'state_or_province_name',
  'locality_name',
  'organization_name',
  'organizational_unit_name',
  'common_name',
  'email_address',
]);

function setCurveOptions(select, values) {
  if (!select) {
    return;
  }
  const selected = select.value;
  select.innerHTML = '';
  values.forEach((value) => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  });
  if (values.includes(selected)) {
    select.value = selected;
  }
}

function updateKeyConfig(container) {
  const algoSelect = container.querySelector('select[name$="key_algorithm"]');
  const curveSelect = container.querySelector('select[name$="curve_name"]');
  const curveField = container.querySelector('[data-curve-field]');
  const rsaFields = container.querySelectorAll('[data-rsa-field]');

  if (!algoSelect) {
    return;
  }

  const algorithm = algoSelect.value;

  if (algorithm === 'rsa') {
    if (curveField) {
      curveField.style.display = 'none';
    }
    rsaFields.forEach((field) => {
      field.style.display = '';
    });
    return;
  }

  if (curveField) {
    curveField.style.display = '';
  }

  if (algorithm === 'ec') {
    setCurveOptions(curveSelect, EC_CURVES);
    rsaFields.forEach((field) => {
      field.style.display = 'none';
    });
    return;
  }

  if (algorithm === 'eddsa') {
    setCurveOptions(curveSelect, EDDSA_CURVES);
    rsaFields.forEach((field) => {
      field.style.display = 'none';
    });
  }
}

function getFieldBySuffix(container, suffix) {
  return container.querySelector(`[name$="${suffix}"]`);
}

function setFieldValue(field, value) {
  if (!field) {
    return;
  }
  if (field.type === 'checkbox') {
    field.checked = Boolean(value);
    return;
  }
  if (value === null || value === undefined) {
    return;
  }
  field.value = String(value);
}

function getFieldSuffix(field) {
  if (!field || !field.name) {
    return '';
  }
  const parts = field.name.split('-');
  return parts[parts.length - 1] || '';
}

function lockProfileBoundFields(container, shouldLock, lockedOptionalSubjectFields = new Set()) {
  const bound = container.querySelectorAll('[data-profile-bound]');
  bound.forEach((section) => {
    const field = section.querySelector('input, select, textarea');
    const suffix = getFieldSuffix(field);
    const isOptionalSubjectField = OPTIONAL_SUBJECT_FIELD_SUFFIXES.has(suffix);
    const lockSection = shouldLock && (!isOptionalSubjectField || lockedOptionalSubjectFields.has(suffix));

    section.classList.toggle('opacity-50', lockSection);
    section.style.pointerEvents = lockSection ? 'none' : '';
  });

  const feedback = container.querySelector('[data-profile-feedback]');
  if (feedback) {
    feedback.textContent = shouldLock
      ? 'Profile is applied: subject, key, and extension fields are locked to profile values.'
      : '';
  }
}

function getProfilePayload() {
  const node = document.getElementById('issue-profile-payload');
  if (!node || !node.textContent) {
    return {};
  }
  try {
    return JSON.parse(node.textContent);
  } catch (error) {
    return {};
  }
}

function applySelectedProfile(container, profileData) {
  const profileSelect = getFieldBySuffix(container, 'certificate_profile');
  if (!profileSelect) {
    return;
  }

  const profile = profileData[profileSelect.value];
  if (!profile) {
    lockProfileBoundFields(container, false);
    updateKeyConfig(container);
    return;
  }

  const lockedOptionalSubjectFields = new Set();

  PROFILE_BOUND_FIELD_SUFFIXES.forEach((suffix) => {
    const field = getFieldBySuffix(container, suffix);
    if (OPTIONAL_SUBJECT_FIELD_SUFFIXES.has(suffix)) {
      const value = profile[suffix];
      if (value === null || value === undefined || String(value).trim() === '') {
        return;
      }
      setFieldValue(field, value);
      lockedOptionalSubjectFields.add(suffix);
      return;
    }

    setFieldValue(field, profile[suffix]);
  });

  updateKeyConfig(container);
  lockProfileBoundFields(container, true, lockedOptionalSubjectFields);
}

function initWorkbench() {
  const profileData = getProfilePayload();

  document.querySelectorAll('[data-key-config-container]').forEach((container) => {
    const algoSelect = container.querySelector('select[name$="key_algorithm"]');
    const profileSelect = container.querySelector('select[name$="certificate_profile"]');

    updateKeyConfig(container);

    if (algoSelect) {
      algoSelect.addEventListener('change', () => updateKeyConfig(container));
    }

    if (profileSelect) {
      applySelectedProfile(container, profileData);
      profileSelect.addEventListener('change', () => applySelectedProfile(container, profileData));
    }
  });
}

window.addEventListener('DOMContentLoaded', initWorkbench);
