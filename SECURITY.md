# Seguridad de CEI Nexus

## Datos protegidos

La plataforma puede contener datos sensibles de investigación, documentos regulatorios, información de seguridad, conflictos de interés, firmas y decisiones institucionales. Debe tratarse como un sistema crítico.

## Controles incorporados

- PostgreSQL con rol de ejecución separado y Row-Level Security.
- Consultas parametrizadas.
- Contraseñas Argon2id.
- MFA TOTP, códigos de recuperación y bloqueo temporal.
- Cifrado documental AES-256-GCM antes de enviar objetos a S3/MinIO.
- Versionado y Object Lock para retención.
- Hash SHA-256 de documentos en claro y cifrados.
- Firma PDF PAdES.
- Registro append-only encadenado por hashes.
- Anclas externas WORM de la auditoría.
- Secretos fuera del repositorio.
- Contenedor de aplicación sin privilegios root.

## Límites de esta versión

- TOTP no es resistente al phishing como WebAuthn/FIDO2.
- La carga de PKCS#12 al servidor es menos segura que HSM, PKCS#11 o firma remota.
- MinIO se ejecuta sin TLS dentro del entorno demostrativo.
- No se incluye antivirus documental ni DLP.
- No se incluye SSO ni ciclo automático de bajas.
- No se incluye un SIEM ni monitoreo 24/7.
- La inmutabilidad absoluta requiere separar administración de la base, anclas externas y controles organizacionales.

## Requisitos para producción

1. TLS en proxy, aplicación, PostgreSQL y almacenamiento.
2. Gestor de secretos y rotación planificada.
3. MFA WebAuthn/FIDO2 para administradores y firmantes.
4. HSM o proveedor de firma remota.
5. Cuenta S3 de mínimo privilegio y KMS/HSM para claves maestras.
6. Escaneo antivirus de cargas y validación de tipos reales de archivo.
7. Backups cifrados, inmutables y probados.
8. Registro centralizado y alertas de seguridad.
9. Revisión de código, SAST, DAST y prueba de penetración.
10. Evaluación de impacto en privacidad y procedimiento de incidentes.
11. Separación de ambientes y datos anonimizados en prueba.
12. Revisión periódica de usuarios, roles, conflictos y accesos.

## Reporte de vulnerabilidades

No publique información sensible ni pruebas con datos reales. Informe el hallazgo al responsable de seguridad de la institución mediante un canal autenticado y cifrado.
