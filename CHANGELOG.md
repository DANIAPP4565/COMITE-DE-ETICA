# Changelog

## 2.0.0 — Arquitectura institucional

- SQLite reemplazado por PostgreSQL.
- Rol propietario separado del rol de ejecución.
- Row-Level Security por rol, autoría y asignación.
- Documentos migrados a almacenamiento S3/MinIO cifrado con AES-256-GCM.
- Versionado, retención, Object Lock y legal hold.
- Contraseñas Argon2id, MFA TOTP, recuperación y bloqueo de acceso.
- Firma digital PDF PAdES con reautenticación MFA.
- Auditoría append-only con cadena de hashes y anclas WORM.
- Workflow por POE en YAML, versionado y activable desde Administración.
- Matriz para mapear los POE reales del Comité.
- Migrador asistido desde la base SQLite del MVP anterior.
- Docker Compose con PostgreSQL, MinIO, migración y aplicación.
- Pruebas locales de reglas, workflow, MFA y firma PDF.
