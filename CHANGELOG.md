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

## 2026-07-18.2 - Corrección Streamlit Cloud

- Eliminada la dependencia de arranque `from cei_core.audit import ...` de `app.py`.
- Las funciones de sellado y consulta de anclajes de auditoría quedan integradas también en `app.py`.
- Agregado `cei_core/config.py` para leer tanto variables de entorno como Streamlit Secrets.
- Agregados `runtime.txt`, ejemplo de secretos, manifiesto del repositorio y prueba `scripts/preflight.py`.
- Agregado workflow de GitHub Actions para detectar archivos faltantes e importaciones rotas antes del despliegue.
