# CEI Nexus — arranque simple

Todo el stack (aplicación + PostgreSQL + almacenamiento de documentos) está
empaquetado. No hay que configurar nada para probarlo.

## Requisito único

Tener **Docker Desktop** instalado (incluye `docker compose`).

## Correr la app (un solo comando)

Desde esta carpeta:

    docker compose up

La primera vez descarga las imágenes y compila; luego abre:

- Aplicación: http://localhost:8501
- Consola de archivos (MinIO, opcional): http://localhost:9001

La base de datos y su esquema se crean **solos** en el primer arranque
(`AUTO_INIT_DB=true`). No hace falta token ni pasos manuales.

Para detener:  `Ctrl+C`  y luego  `docker compose down`
Para empezar de cero (borrar datos):  `docker compose down -v`

## Usuarios de demostración

Con `SEED_DEMO_DATA=true` (por defecto) se cargan usuarios de prueba, por ejemplo:

- usuario `admin` / contraseña `AdminCEI-2026!`
- usuario `presidente` / contraseña `Presidencia-2026!`
- usuario `revisor` / contraseña `RevisorCEI-2026!`

Para un entorno limpio sin datos de ejemplo, poné `SEED_DEMO_DATA=false` en `.env`.

## Qué se simplificó

- **Una sola variable de base de datos**: `DATABASE_URL`. Ya no hacen falta
  `DATABASE_ADMIN_URL` ni `SETUP_TOKEN` para el arranque normal.
- **Esquema automático**: se inicializa en el primer boot.
- **Pool de conexiones** (Psycopg 3): la app reutiliza conexiones en lugar de
  abrir una nueva por cada consulta. Es más rápido y no agota las conexiones de
  PostgreSQL con varios usuarios. Ajustable con `DB_POOL_MIN_SIZE` /
  `DB_POOL_MAX_SIZE`.
- **Seguridad por fila (RLS)**: la identidad del usuario se fija por transacción,
  para que el pool no filtre contexto entre usuarios.

## Usar tu propio PostgreSQL (opcional)

Si ya tenés una base robusta (Neon, Supabase, RDS, on-prem), no necesitás Docker
para la base: corré solo la app y apuntá una única URL.

    pip install -r requirements.txt
    export DATABASE_URL="postgresql://usuario:clave@host:5432/base?sslmode=require"
    streamlit run app.py

El esquema se crea solo. Para documentos cifrados, definí también
`DOCUMENT_MASTER_KEY_B64` y las variables `S3_*` (ver `.env`).

## Producción

Antes de exponerla: cambiá `POSTGRES_PASSWORD`, las claves `S3_*` y generá una
`DOCUMENT_MASTER_KEY_B64` nueva:

    python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
