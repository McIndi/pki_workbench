# PKI Workbench

PKI Workbench is a Django-based certificate authority management application for building and operating private PKI workflows. It supports root/intermediate CAs, end-entity issuance, certificate profiles, artifact downloads, and a REST API surface for integration.

## Status / Disclaimer

**This project is not yet production-ready.**

It is suitable for development, testing, and internal prototyping. Before production deployment, you should complete hardening tasks such as secure secret management, strict host/TLS config, production-grade database/storage choices, observability, backup/recovery strategy, and security review.

## Major Features

- Root CA creation with configurable key algorithm and certification depth
- Intermediate CA creation with depth validation against root policy
- End-entity certificate issuance with:
  - Key algorithm/curve/key-size controls
  - SAN DNS support
  - Key Usage and Extended Key Usage controls
- Certificate Profiles for reusable issuance policy
  - Key/extension defaults
  - Optional subject constraints
  - Derive profile from an issued certificate
  - Edit profiles via UI
- Artifact management
  - Certificate detail page
  - Download public cert, cert chain, CSR, and cert/key bundle zip
  - Consistent artifact filename conventions
- CA Workbench UX
  - Trust chain links
  - Searchable CA and profile selectors
  - Profile-driven issue form auto-fill and field locking
- Home dashboard
  - Counts (CAs, certificates, profiles)
  - Certificates closest to expiration
  - Recursive, clickable CA hierarchy
- REST API (`/api/`)
  - Owner-scoped resources for CAs, certificates, and profiles
  - Dashboard endpoint
  - Workflow endpoints that call existing validated domain workflows
  - OpenAPI schema endpoint at `/api/schema/`

## Tech Stack

- Python 3.14+
- Django 6
- Django REST Framework
- `cryptography`
- `django-environ`
- `django-filter`

## Project Structure (high level)

- `config/` – Django project configuration (`settings.py`, `urls.py`, etc.)
- `pki/` – PKI models, forms, workflows, views, API endpoints, tests
- `accounts/` – authentication/user profile support
- `templates/` – HTML templates
- `requirements.txt` – Python dependencies
- `.env.example` – environment variable reference

## Installation

1. Clone and enter the project:

```bash
git clone <your-repo-url>
cd pki_workbench
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create your environment file:

```bash
cp .env.example .env
```

5. Set a real secret key in `.env`:

```env
DJANGO_SECRET_KEY=<your-strong-secret-key>
```

6. Run migrations:

```bash
python manage.py migrate
```

7. (Optional) Create a superuser:

```bash
python manage.py createsuperuser
```

8. Run the development server:

```bash
python manage.py runserver
```

Open `http://127.0.0.1:8000/`.

## Configuration

Configuration is environment-driven via `django-environ`.

- Settings are loaded from real environment variables and `.env`.
- `DJANGO_SECRET_KEY` is **required**. Startup fails early with an informative error if missing.
- Defaults for non-sensitive settings are documented in `.env.example`.

### Supported environment variables

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

## API Quick Start

- API root index: `GET /api/`
- OpenAPI schema: `GET /api/schema/`

Primary endpoint groups:

- `/api/cas/`
- `/api/certificates/`
- `/api/profiles/`
- `/api/dashboard/`
- `/api/workflows/root-cas/`
- `/api/workflows/intermediate-cas/`
- `/api/workflows/certificates/`
- `/api/workflows/profiles/from-certificate/`

## Running Tests

Run full suite:

```bash
python manage.py test
```

Run focused suites:

```bash
python manage.py test pki.tests_views
python manage.py test pki.tests_api
```

## Production Readiness Checklist (recommended next steps)

- Set `DJANGO_DEBUG=False`
- Configure strict `DJANGO_ALLOWED_HOSTS` and `DJANGO_CSRF_TRUSTED_ORIGINS`
- Use production secret/key management (not plaintext `.env` in runtime environments)
- Use a production database and backup strategy
- Add HTTPS termination and security headers
- Add structured logging/monitoring/alerting
- Review API auth strategy (session/basic vs token/JWT)
- Perform security and compliance review for key/cert handling

## License

GPLv3
