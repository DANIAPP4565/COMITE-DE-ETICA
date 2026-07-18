# CEI Nexus FIX7 — archivo único

Esta edición elimina por completo el error `No module named 'cei_core'`.

El repositorio de GitHub necesita únicamente:

```text
app.py
requirements.txt
runtime.txt
```

La carpeta `cei_core`, los estilos, el workflow y la base de conocimiento
están comprimidos dentro de `app.py` y se extraen automáticamente en el
directorio temporal de Streamlit.

## Despliegue

1. Vaciar el repositorio anterior.
2. Subir solamente los tres archivos indicados.
3. Crear una app nueva en Streamlit Community Cloud.
4. Seleccionar Python 3.12 y `app.py`.
5. Cargar nuevamente los Secrets.
6. Confirmar el build:
   `CEI-NEXUS-FIX7-ARCHIVO-UNICO-20260718`.
