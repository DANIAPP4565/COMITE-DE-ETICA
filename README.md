# CEI Nexus — Plataforma profesional para Comité de Ética en Investigación

CEI Nexus es una aplicación web para gestionar el ciclo completo de evaluación y seguimiento de investigaciones en salud: recepción, control documental, asignación, revisión, observaciones, sesiones, dictámenes, seguridad, enmiendas, supervisión, capacitación y cierre.

Esta versión reemplaza el almacenamiento local del MVP anterior por una arquitectura con **PostgreSQL**, **almacenamiento de objetos cifrado**, **MFA**, **firma digital PDF**, **auditoría encadenada e inmutable** y **workflow versionado por POE**.

## Cambios principales

### PostgreSQL

- PostgreSQL como única base transaccional.
- Tipos nativos para fechas, JSONB, booleanos y UUID.
- Separación entre rol propietario de migraciones y rol de ejecución de la aplicación.
- Políticas PostgreSQL Row-Level Security para limitar expedientes y objetos según rol, asignación y autoría.
- Restricciones de integridad, índices y funciones de verificación.
- Script opcional para migrar datos tabulares desde el SQLite del MVP anterior.

### Documentos seguros

- Almacenamiento S3 compatible; el entorno local usa MinIO.
- Cifrado del lado de la aplicación con **AES-256-GCM**.
- Cálculo y validación de SHA-256 del documento en claro y del sobre cifrado.
- Versionado de objetos.
- Retención configurable y soporte de Object Lock/WORM.
- Legal hold para dictámenes firmados y anclas de auditoría.
- Los archivos PKCS#12 utilizados para firmar se procesan solo en memoria y no se guardan.

### Autenticación multifactor

- Contraseñas nuevas con Argon2id.
- Compatibilidad temporal con hashes PBKDF2 del MVP anterior.
- MFA TOTP mediante aplicaciones autenticadoras.
- Códigos de recuperación de un solo uso.
- Bloqueo temporal por intentos fallidos.
- MFA obligatorio configurable por rol.
- Reautenticación MFA antes de firmar un dictamen.

### Firma digital

- Firma PDF en perfil PAdES con certificados `.p12` o `.pfx`.
- Registro del hash anterior y posterior a la firma.
- Registro de sujeto, emisor, número de serie y huella SHA-256 del certificado.
- Archivo cifrado y retenido del PDF firmado.
- Preparado para reemplazar el PKCS#12 local por HSM, PKCS#11 o firma remota institucional.

> La validez jurídica depende del certificado empleado, su cadena de confianza, vigencia, revocación, autoridad certificante y normativa aplicable. La aplicación no convierte por sí sola una firma electrónica en firma digital jurídicamente válida.

### Auditoría inmutable

- Log append-only sellado por un trigger PostgreSQL.
- Cada entrada incorpora el hash de la entrada anterior.
- Se impiden `UPDATE` y `DELETE` sobre el log y los eventos de workflow.
- Función de verificación completa de la cadena.
- Anclas externas en almacenamiento WORM con retención y legal hold.
- Exportación del registro para auditorías e inspecciones.

### Workflow por POE

- Definición YAML versionada y validada.
- Estados, transiciones, roles autorizados, documentos obligatorios y requisitos de revisión/quórum.
- Registro append-only de cada transición y su fundamento.
- Carga y activación de nuevas versiones desde Administración.
- Cada expediente conserva la versión del POE utilizada.

La plantilla `config/poe_workflow.yaml` es una base inicial. Debe reemplazarse por el contenido exacto de los **Procedimientos Operativos Estandarizados aprobados por el comité**.

## Inicio con Docker

### 1. Generar secretos

```bash
python scripts/generate_env.py
```

El comando crea `.env` con contraseñas y claves aleatorias. Ese archivo no debe subirse a Git ni enviarse por canales inseguros.

### 2. Iniciar los servicios

```bash
docker compose up --build
```

Servicios:

- Aplicación: `http://localhost:8501`
- Consola MinIO: `http://localhost:9001`
- PostgreSQL y MinIO permanecen en redes internas del compose.

### 3. Credenciales demostrativas

Solo se crean con `SEED_DEMO_DATA=true`:

| Usuario | Contraseña inicial | Rol |
|---|---|---|
| admin | `AdminCEI-2026!` | Administrador |
| secretaria | `Secretaria-2026!` | Secretaría |
| presidente | `Presidencia-2026!` | Presidencia |
| revisor | `RevisorCEI-2026!` | Revisor |
| monitor | `MonitorCEI-2026!` | Monitor |
| investigador | `Investigador-2026!` | Investigador |

Cambie todas las contraseñas y active MFA antes de ingresar información real.


### Crear el primer administrador sin datos demo

Con `SEED_DEMO_DATA=false`:

```bash
CEI_ADMIN_USERNAME=admin_institucional \
CEI_ADMIN_PASSWORD='una-contraseña-larga-y-unica' \
CEI_ADMIN_FULL_NAME='Administrador del CEI' \
python scripts/create_admin.py
```

Active MFA inmediatamente después del primer ingreso.

## Instalación sin Docker

Se necesitan PostgreSQL y un servicio S3 compatible ya configurados.

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate       # Windows
pip install -r requirements.txt
```

Configure como mínimo:

```text
DATABASE_ADMIN_URL=postgresql://...
DATABASE_URL=postgresql://...
DATABASE_RUNTIME_ROLE=cei_app
S3_ENDPOINT_URL=https://...
S3_BUCKET=cei-documents
S3_ACCESS_KEY_ID=...
S3_SECRET_ACCESS_KEY=...
DOCUMENT_MASTER_KEY_B64=...
APP_ENCRYPTION_KEY=...
RECOVERY_CODE_PEPPER=...
```

Luego:

```bash
python scripts/migrate.py
streamlit run app.py
```

## Migración desde el SQLite anterior

```bash
SQLITE_PATH=/ruta/cei_nexus.db \
DATABASE_ADMIN_URL=postgresql://... \
DATABASE_URL=postgresql://... \
python scripts/migrate_sqlite_to_postgres.py
```

La migración copia datos tabulares compatibles. Los documentos deben reimportarse para aplicar cifrado, versionado, retención y verificación de integridad.

## Adaptación a los POE reales

1. Reunir los POE vigentes, anexos, formularios, resoluciones y matrices de responsabilidad.
2. Completar `docs/MAPEO_POE_INSTITUCIONAL.md`.
3. Editar una copia de `config/poe_workflow.yaml`.
4. Definir para cada transición:
   - roles autorizados;
   - documentación obligatoria;
   - plazos;
   - revisión expeditiva o plenaria;
   - requisitos de quórum;
   - firma requerida;
   - comunicaciones y excepciones.
5. Aprobar formalmente la versión.
6. Cargarla en **Administración → POE y workflow**.
7. Ejecutar pruebas con expedientes anonimizados antes de activarla.

## Archivos relevantes

```text
app.py                              Interfaz Streamlit
cei_core/db.py                      PostgreSQL, esquema y auditoría
cei_core/storage.py                 Cifrado y almacenamiento S3
cei_core/security.py                Contraseñas, MFA y recuperación
cei_core/digital_sign.py            Firma PAdES
cei_core/workflow.py                Motor de POE
cei_core/audit.py                   Anclas externas de auditoría
config/poe_workflow.yaml            Workflow inicial
scripts/migrate.py                  Creación/migración PostgreSQL
scripts/generate_env.py             Generación de secretos
scripts/migrate_sqlite_to_postgres.py Migración del MVP anterior
```

## Controles aún necesarios antes de producción institucional

- SSO corporativo y ciclo de alta/baja de usuarios.
- MFA resistente al phishing para roles críticos, idealmente WebAuthn/FIDO2.
- HSM, token criptográfico o firma remota en lugar de cargar claves privadas al navegador.
- Gestor de secretos y rotación de claves.
- TLS interno y externo con certificados válidos.
- Backups cifrados y pruebas de restauración.
- Monitoreo, alertas, SIEM y respuesta a incidentes.
- Pruebas SAST, DAST, dependencia y penetración.
- Evaluación de impacto en privacidad.
- Validación informática proporcional al riesgo.
- Revisión legal y regulatoria local.
- Plan de continuidad y recuperación ante desastre.
- Política de retención y destrucción aprobada.

## Prueba rápida de módulos locales

```bash
python smoke_test.py
```

La prueba cubre reglas de evaluación, MFA y validación del workflow. Las pruebas integrales requieren PostgreSQL y S3/MinIO activos.
