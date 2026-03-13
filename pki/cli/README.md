# PKI API CLI

Standalone Python CLI wrapper for the PKI Workbench REST API.

## Authentication

The CLI supports:

- Basic auth (username/password)

You can pass values via flags or environment variables.

CLI code layout:

- Entrypoint: `python -m pki.cli`
- Console script: `pki` (from `pyproject.toml`)
- Package: `pki/cli/`
- One subcommand per file under `pki/cli/commands/`
- Shared crypto primitives: `pki_shared/` (Django-independent)

To enable the `pki` command in your environment:

```bash
pip install -e .
```

Environment variables:

- `PKI_API_BASE_URL` (default: `http://localhost:8000/api/`)
- `PKI_API_USERNAME`
- `PKI_API_PASSWORD`
- `PKI_API_TIMEOUT` (seconds, default: `30`)

## Usage

Show help:

```bash
python -m pki.cli --help
pki --help
```

Create root CA:

```bash
python -m pki.cli create-root-ca \
  --name "CLI Root" \
  --country-name US \
  --state-or-province-name "New York" \
  --locality-name "New York" \
  --organization-name "PKI Workbench" \
  --common-name "CLI Root"
```

Issue certificate (server generates key):

```bash
python -m pki.cli issue-certificate \
  --issuer-ca-id 1 \
  --name "CLI Leaf" \
  --mode generate \
  --country-name US \
  --state-or-province-name "New York" \
  --locality-name "New York" \
  --organization-name "PKI Workbench" \
  --common-name "leaf.example.com"
```

Issue certificate via BYOK with local CSR generation:

```bash
python -m pki.cli issue-certificate \
  --issuer-ca-id 1 \
  --name "BYOK Leaf" \
  --mode csr \
  --generate-csr \
  --country-name US \
  --state-or-province-name "New York" \
  --locality-name "New York" \
  --organization-name "PKI Workbench" \
  --common-name "byok.example.com" \
  --save-generated-key-file ./byok.key.pem \
  --save-generated-csr-file ./byok.csr.pem
```
