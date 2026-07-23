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

function updateUnifiedMode(container) {
  const sourceModeField = getFieldBySuffix(container, 'source_mode');
  if (!sourceModeField) {
    return;
  }

  const createCaField = getFieldBySuffix(container, 'create_certificate_authority');
  const generatedSections = container.querySelectorAll('[data-mode-generated]');
  const csrSections = container.querySelectorAll('[data-mode-csr]');
  const leafOnlySections = container.querySelectorAll('[data-leaf-options]');
  const createCaSections = container.querySelectorAll('[data-create-ca-options]');

  const isCsrMode = sourceModeField.value === 'csr';
  const isCreateCa = !isCsrMode && createCaField && createCaField.checked;

  generatedSections.forEach((section) => {
    section.style.display = isCsrMode ? 'none' : '';
  });

  csrSections.forEach((section) => {
    section.style.display = isCsrMode ? '' : 'none';
  });

  leafOnlySections.forEach((section) => {
    section.style.display = isCreateCa ? 'none' : '';
  });

  const showCreateCaOptions = isCreateCa;
  createCaSections.forEach((section) => {
    section.style.display = showCreateCaOptions ? '' : 'none';
  });
}

function resetLeafUsageDefaults(container) {
  const defaultTrueSuffixes = new Set([
    'ku_digital_signature',
    'ku_key_encipherment',
    'ku_critical',
    'eku_server_auth',
  ]);
  const leafUsageFieldSuffixes = [
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

  leafUsageFieldSuffixes.forEach((suffix) => {
    const field = getFieldBySuffix(container, suffix);
    if (field && field.type === 'checkbox') {
      field.checked = defaultTrueSuffixes.has(suffix);
    }
  });
}

function initDeleteConfirmations() {
  document.querySelectorAll('form[data-confirm-delete]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const message = form.dataset.confirmMessage || 'Delete this item? This cannot be undone.';
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });
}

function getFormCsrfToken(form) {
  const tokenInput = form.querySelector('input[name="csrfmiddlewaretoken"]');
  return tokenInput ? tokenInput.value : '';
}

function asBool(value) {
  return Boolean(value);
}

function getUnifiedModePayload(form, sourceMode, isCreateCa) {
  const pickValue = (suffix) => {
    const field = getFieldBySuffix(form, suffix);
    if (!field) {
      return '';
    }
    if (field.type === 'checkbox') {
      return asBool(field.checked);
    }
    return field.value;
  };

  const certificateProfileValue = pickValue('certificate_profile');
  const certificateProfileId = certificateProfileValue ? Number(certificateProfileValue) : null;

  const keyUsagePayload = {
    ku_digital_signature: asBool(pickValue('ku_digital_signature')),
    ku_content_commitment: asBool(pickValue('ku_content_commitment')),
    ku_key_encipherment: asBool(pickValue('ku_key_encipherment')),
    ku_data_encipherment: asBool(pickValue('ku_data_encipherment')),
    ku_key_agreement: asBool(pickValue('ku_key_agreement')),
    ku_key_cert_sign: asBool(pickValue('ku_key_cert_sign')),
    ku_crl_sign: asBool(pickValue('ku_crl_sign')),
    ku_encipher_only: asBool(pickValue('ku_encipher_only')),
    ku_decipher_only: asBool(pickValue('ku_decipher_only')),
    ku_critical: asBool(pickValue('ku_critical')),
  };

  const extendedKeyUsagePayload = {
    eku_server_auth: asBool(pickValue('eku_server_auth')),
    eku_client_auth: asBool(pickValue('eku_client_auth')),
    eku_code_signing: asBool(pickValue('eku_code_signing')),
    eku_email_protection: asBool(pickValue('eku_email_protection')),
    eku_time_stamping: asBool(pickValue('eku_time_stamping')),
    eku_ocsp_signing: asBool(pickValue('eku_ocsp_signing')),
  };

  if (sourceMode === 'csr') {
    return {
      payload: {
        name: pickValue('name'),
        csr_pem: pickValue('csr_pem'),
        certificate_profile_id: certificateProfileId,
        issuer_key_passphrase: pickValue('issuer_key_passphrase'),
        days_valid: Number(pickValue('days_valid') || 365),
        ...keyUsagePayload,
        ...extendedKeyUsagePayload,
      },
      requestType: 'csr',
    };
  }

  const generatedBasePayload = {
    name: pickValue('name'),
    country_name: pickValue('country_name'),
    state_or_province_name: pickValue('state_or_province_name'),
    locality_name: pickValue('locality_name'),
    organization_name: pickValue('organization_name'),
    organizational_unit_name: pickValue('organizational_unit_name'),
    common_name: pickValue('common_name'),
    email_address: pickValue('email_address'),
    days_valid: Number(pickValue('days_valid') || 365),
    key_algorithm: pickValue('key_algorithm') || 'rsa',
    curve_name: pickValue('curve_name'),
    key_size: Number(pickValue('key_size') || 2048),
    public_exponent: Number(pickValue('public_exponent') || 65537),
    passphrase: pickValue('passphrase'),
  };

  if (isCreateCa) {
    return {
      payload: {
        ...generatedBasePayload,
        parent_key_passphrase: pickValue('parent_key_passphrase'),
      },
      requestType: 'intermediate',
    };
  }

  return {
    payload: {
      ...generatedBasePayload,
      certificate_profile_id: certificateProfileId,
      issuer_key_passphrase: pickValue('issuer_key_passphrase'),
      san_dns_names: pickValue('san_dns_names'),
      ...keyUsagePayload,
      ...extendedKeyUsagePayload,
    },
    requestType: 'issue',
  };
}

function flattenErrors(data) {
  if (!data || typeof data !== 'object') {
    return ['Unexpected error.'];
  }

  if (typeof data.detail === 'string' && data.detail) {
    return [data.detail];
  }

  if (data.errors && typeof data.errors === 'object') {
    return Object.entries(data.errors).flatMap(([field, values]) => {
      if (Array.isArray(values)) {
        return values.map((value) => `${field}: ${value}`);
      }
      return [`${field}: ${values}`];
    });
  }

  return Object.entries(data).flatMap(([field, values]) => {
    if (Array.isArray(values)) {
      return values.map((value) => `${field}: ${value}`);
    }
    if (typeof values === 'string') {
      return [`${field}: ${values}`];
    }
    return [];
  });
}

function renderUnifiedFeedback(form, type, lines) {
  const feedback = form.querySelector('[data-unified-feedback]');
  if (!feedback) {
    return;
  }

  const cssType = type === 'success' ? 'alert-success' : 'alert-danger';
  feedback.className = `col-12 alert ${cssType} mb-0`;
  feedback.classList.remove('d-none');

  if (!Array.isArray(lines) || !lines.length) {
    feedback.textContent = type === 'success' ? 'Success.' : 'Request failed.';
    return;
  }

  feedback.innerHTML = lines.map((line) => `<div>${line}</div>`).join('');
}

async function submitUnifiedViaApi(form) {
  const sourceModeField = getFieldBySuffix(form, 'source_mode');
  const createCaField = getFieldBySuffix(form, 'create_certificate_authority');
  if (!sourceModeField) {
    return;
  }

  const sourceMode = sourceModeField.value;
  const isCreateCa = sourceMode !== 'csr' && createCaField && createCaField.checked;
  const caId = form.dataset.caId;

  const { payload, requestType } = getUnifiedModePayload(form, sourceMode, isCreateCa);
  let endpoint = '';

  if (requestType === 'csr') {
    endpoint = `/api/cas/${caId}/sign-csr/`;
  } else if (requestType === 'intermediate') {
    endpoint = form.dataset.endpointIntermediate || '/api/workflows/intermediate-cas/';
    payload.parent_ca_id = Number(caId);
  } else {
    endpoint = form.dataset.endpointIssue || '/api/workflows/certificates/';
    payload.issuer_ca_id = Number(caId);
  }

  const submitButton = form.querySelector('button[type="submit"]');
  const priorText = submitButton ? submitButton.textContent : '';
  if (submitButton) {
    submitButton.disabled = true;
    submitButton.textContent = 'Submitting...';
  }

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getFormCsrfToken(form),
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      renderUnifiedFeedback(form, 'error', flattenErrors(data));
      return;
    }

    if (requestType === 'intermediate' && data && data.id) {
      renderUnifiedFeedback(form, 'success', ['Intermediate CA created. Redirecting to child CA workbench...']);
      window.location.assign(`/pki/ca/${data.id}/workbench/`);
      return;
    }

    renderUnifiedFeedback(form, 'success', ['Request completed successfully. Refreshing workbench...']);
    window.location.assign(window.location.href);
  } catch (error) {
    renderUnifiedFeedback(form, 'error', ['Unable to reach API endpoint. Falling back to standard form submit.']);
    form.submit();
  } finally {
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent = priorText;
    }
  }
}

function initUnifiedApiForm() {
  const unifiedForm = document.querySelector('form[data-unified-form]');
  if (!unifiedForm || typeof window.fetch !== 'function') {
    return;
  }

  unifiedForm.addEventListener('submit', (event) => {
    event.preventDefault();
    submitUnifiedViaApi(unifiedForm);
  });
}

function renderManageFeedback(type, lines) {
  const feedback = document.querySelector('[data-manage-feedback]');
  if (!feedback) {
    return;
  }

  feedback.className = `alert ${type === 'success' ? 'alert-success' : 'alert-danger'}`;
  feedback.classList.remove('d-none');

  if (!Array.isArray(lines) || !lines.length) {
    feedback.textContent = type === 'success' ? 'Success.' : 'Request failed.';
    return;
  }

  feedback.innerHTML = lines.map((line) => `<div>${line}</div>`).join('');
}

function buildDeletePayload(form) {
  const payload = {};
  form.querySelectorAll('input[type="hidden"]').forEach((input) => {
    if (!input.name || input.name === 'csrfmiddlewaretoken' || input.name === 'action') {
      return;
    }
    payload[input.name] = input.value;
  });
  return payload;
}

function initManageApiDeleteForms() {
  document.querySelectorAll('form[data-api-delete-form]').forEach((form) => {
    form.addEventListener('submit', async (event) => {
      if (event.defaultPrevented) {
        return;
      }
      event.preventDefault();

      const endpoint = form.dataset.apiEndpoint;
      if (!endpoint || typeof window.fetch !== 'function') {
        form.submit();
        return;
      }

      const submitButton = form.querySelector('button[type="submit"]');
      if (submitButton) {
        submitButton.disabled = true;
      }

      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getFormCsrfToken(form),
          },
          body: JSON.stringify(buildDeletePayload(form)),
        });

        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          renderManageFeedback('error', flattenErrors(data));
          return;
        }

        const successMessage = form.dataset.successMessage || data.detail || 'Delete completed successfully.';
        renderManageFeedback('success', [successMessage]);

        const listItem = form.closest('li');
        if (listItem) {
          listItem.remove();
        }
      } catch (error) {
        renderManageFeedback('error', ['Unable to reach API endpoint. Falling back to standard form submit.']);
        form.submit();
      } finally {
        if (submitButton) {
          submitButton.disabled = false;
        }
      }
    });
  });
}

const PROFILE_BOOL_FIELDS = [
  'is_ca',
  'ku_digital_signature', 'ku_content_commitment', 'ku_key_encipherment',
  'ku_data_encipherment', 'ku_key_agreement', 'ku_key_cert_sign', 'ku_crl_sign',
  'ku_encipher_only', 'ku_decipher_only', 'ku_critical',
  'eku_server_auth', 'eku_client_auth', 'eku_code_signing',
  'eku_email_protection', 'eku_time_stamping', 'eku_ocsp_signing',
];

const PROFILE_INT_FIELDS = ['days_valid', 'key_size', 'public_exponent', 'path_length'];

const PROFILE_TEXT_FIELDS = [
  'name', 'description', 'key_algorithm', 'curve_name',
  'country_name', 'state_or_province_name', 'locality_name',
  'organization_name', 'organizational_unit_name', 'common_name', 'email_address',
];

function buildProfilePayload(form) {
  const prefix = form.dataset.formPrefix ? form.dataset.formPrefix + '-' : '';
  const data = new FormData(form);
  const payload = {};

  PROFILE_TEXT_FIELDS.forEach((field) => {
    const formName = prefix + field;
    if (data.has(formName)) {
      payload[field] = data.get(formName);
    }
  });

  PROFILE_INT_FIELDS.forEach((field) => {
    const val = data.get(prefix + field);
    payload[field] = (val !== null && val !== '') ? parseInt(val, 10) : null;
  });

  // Unchecked checkboxes are absent from FormData — map all explicitly as booleans.
  PROFILE_BOOL_FIELDS.forEach((field) => {
    payload[field] = data.has(prefix + field);
  });

  return payload;
}

function renderProfileFeedback(form, type, lines) {
  const feedback = form.querySelector('[data-profile-feedback]');
  if (!feedback) {
    return;
  }

  feedback.className = `col-12 alert ${type === 'success' ? 'alert-success' : 'alert-danger'}`;

  if (!Array.isArray(lines) || !lines.length) {
    feedback.textContent = type === 'success' ? 'Profile created successfully.' : 'Request failed.';
    return;
  }

  feedback.innerHTML = lines.map((line) => `<div>${line}</div>`).join('');
}

function initProfileApiForm() {
  const form = document.querySelector('form[data-profile-form]');
  if (!form || typeof window.fetch !== 'function') {
    return;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    const endpoint = form.dataset.apiEndpoint;
    if (!endpoint) {
      form.submit();
      return;
    }

    const submitButton = form.querySelector('button[type="submit"]');
    if (submitButton) {
      submitButton.disabled = true;
    }

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getFormCsrfToken(form),
        },
        body: JSON.stringify(buildProfilePayload(form)),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        renderProfileFeedback(form, 'error', flattenErrors(data));
        return;
      }

      renderProfileFeedback(form, 'success', [`Profile "${data.name || ''}" created successfully.`]);
      form.reset();
    } catch (error) {
      renderProfileFeedback(form, 'error', ['Unable to reach API. Falling back to standard form submit.']);
      form.submit();
    } finally {
      if (submitButton) {
        submitButton.disabled = false;
      }
    }
  });
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

    const sourceModeField = getFieldBySuffix(container, 'source_mode');
    if (sourceModeField) {
      updateUnifiedMode(container);
      sourceModeField.addEventListener('change', () => updateUnifiedMode(container));
      const createCaField = getFieldBySuffix(container, 'create_certificate_authority');
      if (createCaField) {
        createCaField.addEventListener('change', () => updateUnifiedMode(container));
      }
    }

    const resetDefaultsButton = container.querySelector('[data-reset-leaf-defaults]');
    if (resetDefaultsButton) {
      resetDefaultsButton.addEventListener('click', () => resetLeafUsageDefaults(container));
    }
  });

  initDeleteConfirmations();
  initUnifiedApiForm();
  initManageApiDeleteForms();
  initProfileApiForm();
}

window.addEventListener('DOMContentLoaded', initWorkbench);
