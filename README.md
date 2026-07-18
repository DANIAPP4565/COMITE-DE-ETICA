# CEI Nexus FIX8 — diagnóstico PostgreSQL integrado

Repositorio mínimo:

```text
app.py
requirements.txt
runtime.txt
```

Esta versión agrega diagnóstico seguro para `DATABASE_URL` y
`DATABASE_ADMIN_URL`, mostrando host, puerto, DNS, conectividad TCP y error
PostgreSQL sin revelar la contraseña.

Para Neon se recomienda:

- `DATABASE_URL`: conexión pooled (`-pooler`) para la aplicación.
- `DATABASE_ADMIN_URL`: conexión directa (sin `-pooler`) para crear/migrar
  el esquema.

Copie ambas cadenas exactamente desde el panel **Connect** de Neon.
No reconstruya manualmente una URL si la contraseña contiene caracteres
especiales.
