---
title: Python API
---

# Python API

This reference is generated from PKI Workbench docstrings and signatures. It
covers the shared crypto helpers, core PKI services, issuance workflows, and
data models.

## Shared crypto helpers

Django-independent primitives used by both the API/server and the CLI (see
`pki_shared/`).

::: pki_shared.crypto.create_private_key

::: pki_shared.crypto.load_private_key

::: pki_shared.crypto.create_csr

## Core PKI services

::: pki.services.create_self_signed_ca

::: pki.services.sign_certificate

::: pki.services.parse_certificate_info

## Issuance workflows

The workflow layer that the API views and Django views both call — request
validation, key generation, and persistence composed into one operation.

::: pki.workflows.create_root_certificate_authority

::: pki.workflows.create_intermediate_certificate_authority

::: pki.workflows.issue_signed_certificate

## Data models

::: pki.models.PrivateKey

::: pki.models.CertificateSigningRequest

::: pki.models.SignedCertificate

::: pki.models.CertificateProfile

::: pki.models.CertificateAuthority
