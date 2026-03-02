function initCopyPem() {
  const source = document.querySelector('[data-copy-pem-source]');
  const button = document.querySelector('[data-copy-pem-button]');
  const feedback = document.querySelector('[data-copy-pem-feedback]');

  if (!source || !button || !feedback) {
    return;
  }

  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(source.value);
      feedback.textContent = 'PEM copied to clipboard.';
      button.textContent = 'Copied';
      setTimeout(() => {
        button.textContent = 'Copy PEM';
        feedback.textContent = '';
      }, 1800);
    } catch (error) {
      feedback.textContent = 'Unable to copy automatically. Please copy manually.';
    }
  });
}

window.addEventListener('DOMContentLoaded', initCopyPem);
