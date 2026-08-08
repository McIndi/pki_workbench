---
title: Configuration
---

# Configuration

Configuration is environment-driven via `django-environ`.

- Settings are loaded from real environment variables and `.env`.
- `DJANGO_SECRET_KEY` is **required**. Startup fails early with an
  informative error if missing.
- Defaults for non-sensitive settings are documented in `.env.example`.

## Supported environment variables

- `DJANGO_SECRET_KEY` (required)
- `DJANGO_DEBUG` (default: `True`)
- `DJANGO_ALLOWED_HOSTS` (default: empty)
- `DJANGO_CSRF_TRUSTED_ORIGINS` (default: empty)
- `DJANGO_DB_URL` (default: `sqlite:///db.sqlite3`)
- `DJANGO_LANGUAGE_CODE` (default: `en-us`)
- `DJANGO_TIME_ZONE` (default: `UTC`)
- `DJANGO_USE_I18N` (default: `True`)
- `DJANGO_USE_TZ` (default: `True`)
- `DJANGO_STATIC_URL` (default: `static/`)
- `DJANGO_LOGIN_URL` (default: `login`)
- `DJANGO_LOGIN_REDIRECT_URL` (default: `profile`)
- `DJANGO_LOGOUT_REDIRECT_URL` (default: `login`)
- `DJANGO_DEFAULT_AUTO_FIELD` (default: `django.db.models.BigAutoField`)
- `DJANGO_FERNET_SALT_KEYS` (optional, comma-separated for key rotation) —
  derivation salt(s) for the encrypted private-key field
- `DJANGO_SALT_KEY` (optional) — legacy single-key alias for
  `DJANGO_FERNET_SALT_KEYS`

## CLI configuration

The `pki_cli` wrapper reads its own environment variables — see the
[CLI guide](cli.md).

Before deploying beyond local development, see the
[Production Readiness Checklist](production-checklist.md).
