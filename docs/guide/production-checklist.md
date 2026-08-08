---
title: Production Readiness Checklist
---

# Production Readiness Checklist

PKI Workbench is not yet production-ready. Before deploying beyond local
development or internal prototyping, work through this list:

- Set `DJANGO_DEBUG=False`
- Configure strict `DJANGO_ALLOWED_HOSTS` and `DJANGO_CSRF_TRUSTED_ORIGINS`
- Use production secret/key management (not plaintext `.env` in runtime
  environments)
- Use a production database and backup strategy
- Add HTTPS termination and security headers
- Ensure `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`, and
  `DJANGO_CSRF_TRUSTED_ORIGINS` are explicitly set before any non-local
  deployment; treat the defaults as development-only convenience.
- If you use the CLI's Basic auth option, require HTTPS for all API traffic
  so credentials are not exposed on the wire.
- Add structured logging/monitoring/alerting
- Review API auth strategy (session/basic vs token/JWT)
- Perform security and compliance review for key/cert handling

See [Configuration](configuration.md) for the environment variables involved.
