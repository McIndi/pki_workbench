---
title: Installation
---

# Installation

1. Clone and enter the project:

```bash
git clone https://github.com/McIndi/pki_workbench.git
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

## Project structure (high level)

- `config/` – Django project configuration (`settings.py`, `urls.py`, etc.)
- `pki/` – PKI models, forms, workflows, views, API endpoints, tests
- `pki_shared/` – shared non-Django crypto helpers used by API/server and CLI
- `accounts/` – authentication/user profile support
- `templates/` – HTML templates
- `requirements.txt` – Python dependencies
- `.env.example` – environment variable reference

## Running tests

Run full suite:

```bash
python manage.py test
```

Run focused suites:

```bash
python manage.py test pki.tests_views
python manage.py test pki.tests_api
python manage.py test pki.tests_cli
```
