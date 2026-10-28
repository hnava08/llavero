# Llavero

API para crear una cuenta, entrar, emitir llaves y guardar apuntes. La sesión administra las llaves. La llave lee o escribe los apuntes, según el alcance que se le dio.

Harold Nava

## Correrla

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --port 8010
```

La documentación de las rutas queda en `http://127.0.0.1:8010/docs`. Las pruebas:

```bash
.venv/bin/pytest
```

La base es un archivo SQLite, `llavero.db`. En producción la firma de la sesión sale de `LLAVERO_SECRETO` (ver `.env.example`).

## Peticiones

Crear la cuenta:

```bash
curl -s -X POST http://127.0.0.1:8010/v1/cuentas \
  -H 'content-type: application/json' \
  -d '{"nombre":"Harold Nava","correo":"harold@ejemplo.bo","clave":"ribera-segura"}'
```

Entrar. La respuesta trae el token de sesión:

```bash
curl -s -X POST http://127.0.0.1:8010/v1/sesion \
  -H 'content-type: application/json' \
  -d '{"correo":"harold@ejemplo.bo","clave":"ribera-segura"}'
```

Emitir una llave. El secreto vuelve una sola vez:

```bash
curl -s -X POST http://127.0.0.1:8010/v1/llaves \
  -H 'authorization: Bearer ses_...' \
  -H 'content-type: application/json' \
  -d '{"nombre":"carga","alcance":"escritura"}'
```

Escribir un apunte con esa llave:

```bash
curl -s -X POST http://127.0.0.1:8010/v1/apuntes \
  -H 'authorization: Bearer llv_...' \
  -H 'content-type: application/json' \
  -d '{"texto":"Cerrar el local a las 8"}'
```

## Reglas

- `Authorization: Bearer` acompaña cada ruta privada. La sesión (`ses_`) crea y revoca llaves. La llave (`llv_`) lee o escribe apuntes.
- `lectura` puede listar. `escritura` también crea y borra. Si no alcanza, la respuesta es 403.
- Un apunte de otra cuenta responde 404.
- La clave se guarda con PBKDF2. El secreto de la llave se guarda con SHA-256 y no vuelve en el listado.
- Entrar con un correo desconocido o una clave mala devuelve el mismo 401. Crear cuenta con un correo repetido devuelve 409.
- `/v1/sesion` acepta 8 intentos por minuto y por dirección. El siguiente responde 429 con `Retry-After`.
- El cuerpo no pasa de 16 KB. Una petición mal formada responde 422 sin repetir lo que se envió.
- Las respuestas llevan `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` y `Cache-Control: no-store`.
