---
title: API Quick Start
---

# API Quick Start

- API root index: `GET /api/`
- OpenAPI schema: `GET /api/schema/`

The root index lists the absolute URL for every resource and workflow
endpoint, including detail-URL templates, so a client can discover the full
API surface from a single request instead of hardcoding paths.

## Primary endpoint groups

- `/api/cas/` — read-only certificate authority resources, plus
  `chain`, `children`, and `sign-csr` actions on individual CAs
- `/api/certificates/` — read-only issued-certificate resources
- `/api/profiles/` — full CRUD for certificate profiles
- `/api/dashboard/` — counts and expiring-certificate summary
- `/api/workflows/root-cas/` — create a root CA
- `/api/workflows/intermediate-cas/` — create an intermediate CA under a
  parent the caller owns
- `/api/workflows/import-ca/` — import an externally issued CA
  certificate/key pair
- `/api/workflows/certificates/` — issue an end-entity certificate with
  server-generated key material
- `/api/workflows/delete-certificate/`, `/api/workflows/delete-ca/`,
  `/api/workflows/delete-private-key/`, `/api/workflows/delete-csr/` —
  delete a resource the caller owns
- `/api/workflows/profiles/from-certificate/` — derive a reusable profile
  from an existing certificate

See the [REST API reference](../reference/rest-api.md) for the full request
and response schema of every endpoint, generated from the running app's
route definitions.

## Typical issuance flow

1. `POST /api/workflows/root-cas/` to create a root CA.
2. `POST /api/workflows/intermediate-cas/` to create one or more
   intermediate CAs under it (optional — you can also issue directly from
   the root).
3. Optionally define a `CertificateProfile` via `/api/profiles/`, or derive
   one later from an issued certificate.
4. `POST /api/workflows/certificates/` (server-generated key) or
   `POST /api/cas/{id}/sign-csr/` (bring-your-own-key/CSR) to issue an
   end-entity certificate.

Authentication uses Django REST Framework session or Basic auth
(`config/settings.py`'s `REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]`).
All endpoints require an authenticated user and are scoped to that user's
own resources.
