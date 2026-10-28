import secrets
import sqlite3
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from app.ajustes import Ajustes, desde_entorno
from app import almacen
from app.seguridad import (
    HASH_FIJO,
    Limitador,
    clave_ok,
    emitir_sesion,
    hash_clave,
    hash_llave,
    leer_sesion,
    nueva_llave,
    prefijo_de,
)

MENSAJE_ENTRADA = "Correo o clave incorrectos."
MENSAJE_LLAVE = "La llave no sirve."


class CuentaIn(BaseModel):
    nombre: str = Field(min_length=3, max_length=80)
    correo: str = Field(min_length=6, max_length=160, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    clave: str = Field(min_length=8, max_length=72)


class SesionIn(BaseModel):
    correo: str = Field(min_length=6, max_length=160)
    clave: str = Field(min_length=1, max_length=72)


class LlaveIn(BaseModel):
    nombre: str = Field(min_length=2, max_length=80)
    alcance: str = Field(pattern=r"^(lectura|escritura)$")


class ApunteIn(BaseModel):
    texto: str = Field(min_length=1, max_length=500)


def error(status: int, codigo: str, mensaje: str, headers: Optional[dict] = None) -> HTTPException:
    return HTTPException(status_code=status, detail={"codigo": codigo, "mensaje": mensaje}, headers=headers)


def crear_app(ajustes: Optional[Ajustes] = None) -> FastAPI:
    ajustes = ajustes or desde_entorno()
    app = FastAPI(title="Llavero", version="1")
    app.state.ajustes = ajustes
    app.state.limite = Limitador(ajustes.limite, ajustes.ventana)

    conn = almacen.conectar(ajustes.db_path)
    try:
        almacen.iniciar(conn)
        conn.commit()
    finally:
        conn.close()

    def db():
        conn = almacen.conectar(ajustes.db_path)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def credencial(
        request: Request,
        authorization: Optional[str] = Header(default=None),
        conn: sqlite3.Connection = Depends(db),
    ) -> dict:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise error(401, "no_autorizado", "Falta el encabezado Authorization.")
        token = authorization.split(" ", 1)[1].strip()
        if token.startswith("ses_"):
            cuenta_id = leer_sesion(token, request.app.state.ajustes.secreto)
            if not cuenta_id or not almacen.cuenta_por_id(conn, cuenta_id):
                raise error(401, "no_autorizado", "La sesión no sirve.")
            return {"tipo": "sesion", "cuenta_id": cuenta_id}
        digest = hash_llave(token)
        prefijo = prefijo_de(token)
        fila = almacen.llave_por_prefijo(conn, prefijo) if prefijo else None
        coincide = bool(fila) and secrets.compare_digest(digest, fila["secreto_hash"])
        if not coincide or fila["revocada"]:
            raise error(401, "no_autorizado", MENSAJE_LLAVE)
        return {
            "tipo": "llave",
            "cuenta_id": fila["cuenta_id"],
            "alcance": fila["alcance"],
            "llave_id": fila["id"],
        }

    def sesion(datos: dict = Depends(credencial)) -> dict:
        if datos["tipo"] != "sesion":
            raise error(401, "sesion_requerida", "Esta ruta pide una sesión, no una llave.")
        return datos

    def llave(datos: dict = Depends(credencial)) -> dict:
        if datos["tipo"] != "llave":
            raise error(401, "llave_requerida", "Esta ruta pide una llave.")
        return datos

    def escritura(datos: dict = Depends(llave)) -> dict:
        if datos["alcance"] != "escritura":
            raise error(403, "sin_alcance", "Esta llave solo puede leer.")
        return datos

    @app.middleware("http")
    async def limites(request: Request, call_next):
        largo = request.headers.get("content-length")
        if largo and largo.isdigit() and int(largo) > 16_384:
            return JSONResponse(
                status_code=413,
                content={"error": {"codigo": "cuerpo_grande", "mensaje": "El cuerpo pasa el límite."}},
            )
        respuesta = await call_next(request)
        respuesta.headers["X-Content-Type-Options"] = "nosniff"
        respuesta.headers["X-Frame-Options"] = "DENY"
        respuesta.headers["Referrer-Policy"] = "no-referrer"
        respuesta.headers["Cache-Control"] = "no-store"
        return respuesta

    @app.exception_handler(HTTPException)
    async def http_error(_request, exc: HTTPException):
        detalle = exc.detail
        if isinstance(detalle, dict) and "codigo" in detalle:
            cuerpo = {"error": detalle}
        else:
            cuerpo = {"error": {"codigo": "error", "mensaje": str(detalle)}}
        return JSONResponse(status_code=exc.status_code, content=cuerpo, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def solicitud_invalida(_request, _exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={"error": {"codigo": "solicitud_invalida", "mensaje": "Revisa el cuerpo de la petición."}},
        )

    @app.get("/", include_in_schema=False)
    def inicio():
        return RedirectResponse("/docs")

    @app.get("/v1/salud")
    def salud():
        return {"ok": True}

    @app.post("/v1/cuentas", status_code=201)
    def crear_cuenta(body: CuentaIn, conn: sqlite3.Connection = Depends(db)):
        correo = body.correo.strip().lower()
        if almacen.cuenta_por_correo(conn, correo):
            raise error(409, "correo_en_uso", "Ese correo ya tiene cuenta.")
        return almacen.crear_cuenta(conn, body.nombre.strip(), correo, hash_clave(body.clave))

    @app.post("/v1/sesion")
    def abrir_sesion(body: SesionIn, request: Request, conn: sqlite3.Connection = Depends(db)):
        ip = request.client.host if request.client else "sin-ip"
        if not request.app.state.limite.permitir(ip):
            raise error(
                429,
                "demasiadas_solicitudes",
                "Espera un momento e intenta de nuevo.",
                headers={"Retry-After": str(request.app.state.ajustes.ventana)},
            )
        fila = almacen.cuenta_por_correo(conn, body.correo.strip().lower())
        guardada = fila["clave_hash"] if fila else HASH_FIJO
        # Si el correo no existe, igual se calcula el hash para no delatarlo por el tiempo.
        coincide = clave_ok(body.clave, guardada)
        if not fila or not coincide:
            raise error(401, "no_autorizado", MENSAJE_ENTRADA)
        token, expira = emitir_sesion(fila["id"], request.app.state.ajustes.secreto, request.app.state.ajustes.ttl)
        return {"token": token, "tipo": "Bearer", "expira": expira}

    @app.get("/v1/yo")
    def yo(datos: dict = Depends(credencial), conn: sqlite3.Connection = Depends(db)):
        cuenta = almacen.cuenta_por_id(conn, datos["cuenta_id"])
        salida = {"tipo": datos["tipo"], "cuenta": dict(cuenta)}
        if datos["tipo"] == "llave":
            salida["alcance"] = datos["alcance"]
        return salida

    @app.post("/v1/llaves", status_code=201)
    def crear_llave(body: LlaveIn, datos: dict = Depends(sesion), conn: sqlite3.Connection = Depends(db)):
        for _ in range(3):
            secreto = nueva_llave()
            prefijo = prefijo_de(secreto)
            try:
                publica = almacen.crear_llave(
                    conn, datos["cuenta_id"], body.nombre.strip(), body.alcance, prefijo, hash_llave(secreto)
                )
            except sqlite3.IntegrityError:
                conn.rollback()
                continue
            return {**publica, "secreto": secreto}
        raise error(500, "error_interno", "No se pudo crear la llave.")

    @app.get("/v1/llaves")
    def listar_llaves(datos: dict = Depends(sesion), conn: sqlite3.Connection = Depends(db)):
        return {"llaves": almacen.llaves_de(conn, datos["cuenta_id"])}

    @app.delete("/v1/llaves/{llave_id}", status_code=204)
    def revocar(llave_id: str, datos: dict = Depends(sesion), conn: sqlite3.Connection = Depends(db)):
        if not almacen.revocar_llave(conn, llave_id, datos["cuenta_id"]):
            raise error(404, "no_encontrada", "Esa llave no está.")
        return Response(status_code=204)

    @app.get("/v1/apuntes")
    def listar_apuntes(datos: dict = Depends(llave), conn: sqlite3.Connection = Depends(db)):
        return {"apuntes": almacen.apuntes_de(conn, datos["cuenta_id"])}

    @app.post("/v1/apuntes", status_code=201)
    def crear_apunte(body: ApunteIn, datos: dict = Depends(escritura), conn: sqlite3.Connection = Depends(db)):
        return almacen.crear_apunte(conn, datos["cuenta_id"], body.texto.strip())

    @app.delete("/v1/apuntes/{apunte_id}", status_code=204)
    def borrar_apunte(apunte_id: str, datos: dict = Depends(escritura), conn: sqlite3.Connection = Depends(db)):
        if not almacen.borrar_apunte(conn, apunte_id, datos["cuenta_id"]):
            raise error(404, "no_encontrado", "Ese apunte no está.")
        return Response(status_code=204)

    return app


app = crear_app()
