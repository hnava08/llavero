import sqlite3

from fastapi.testclient import TestClient

from app.ajustes import Ajustes
from app.main import MENSAJE_ENTRADA, MENSAJE_LLAVE, crear_app


def cliente(tmp_path, limite=8):
    ajustes = Ajustes(
        db_path=str(tmp_path / "llavero.db"),
        secreto="secreto-de-prueba",
        limite=limite,
        ventana=60,
        ttl=3600,
    )
    return TestClient(crear_app(ajustes))


def cuenta(http, correo="harold@ejemplo.bo", clave="ribera-segura"):
    alta = http.post("/v1/cuentas", json={"nombre": "Harold Nava", "correo": correo, "clave": clave})
    assert alta.status_code == 201
    sesion = http.post("/v1/sesion", json={"correo": correo, "clave": clave})
    assert sesion.status_code == 200
    return alta.json(), sesion.json()["token"]


def llave(http, token, alcance="escritura", nombre="script"):
    alta = http.post(
        "/v1/llaves",
        json={"nombre": nombre, "alcance": alcance},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert alta.status_code == 201
    return alta.json()


def test_flujo_de_apuntes(tmp_path):
    http = cliente(tmp_path)
    _cuenta, token = cuenta(http)
    lectura = llave(http, token, "lectura", "consulta")
    escritura = llave(http, token, "escritura", "carga")

    ver = http.get("/v1/apuntes", headers={"Authorization": f"Bearer {lectura['secreto']}"})
    assert ver.status_code == 200
    assert ver.json()["apuntes"] == []

    bloqueo = http.post(
        "/v1/apuntes",
        json={"texto": "no debe entrar"},
        headers={"Authorization": f"Bearer {lectura['secreto']}"},
    )
    assert bloqueo.status_code == 403
    assert bloqueo.json()["error"]["codigo"] == "sin_alcance"

    alta = http.post(
        "/v1/apuntes",
        json={"texto": "Cerrar el local a las 8"},
        headers={"Authorization": f"Bearer {escritura['secreto']}"},
    )
    assert alta.status_code == 201
    apunte_id = alta.json()["id"]

    lista = http.get("/v1/apuntes", headers={"Authorization": f"Bearer {lectura['secreto']}"})
    assert lista.json()["apuntes"][0]["texto"] == "Cerrar el local a las 8"

    borrar = http.delete(
        f"/v1/apuntes/{apunte_id}",
        headers={"Authorization": f"Bearer {escritura['secreto']}"},
    )
    assert borrar.status_code == 204
    assert http.get("/v1/apuntes", headers={"Authorization": f"Bearer {lectura['secreto']}"}).json()["apuntes"] == []


def test_la_sesion_y_la_llave_no_se_cruzan(tmp_path):
    http = cliente(tmp_path)
    _cuenta, token = cuenta(http)
    secreta = llave(http, token)["secreto"]
    sesion = {"Authorization": f"Bearer {token}"}
    bearer = {"Authorization": f"Bearer {secreta}"}

    assert http.get("/v1/apuntes", headers=sesion).status_code == 401
    assert http.post("/v1/llaves", json={"nombre": "otra", "alcance": "lectura"}, headers=bearer).status_code == 401
    assert http.get("/v1/llaves", headers=sesion).json()["llaves"][0]["prefijo"] == secreta[:12]
    assert "secreto" not in http.get("/v1/llaves", headers=sesion).json()["llaves"][0]


def test_el_secreto_no_queda_en_la_base(tmp_path):
    http = cliente(tmp_path)
    _cuenta, token = cuenta(http)
    secreta = llave(http, token)["secreto"]
    crudo = (tmp_path / "llavero.db").read_bytes()
    assert secreta.encode() not in crudo
    assert b"ribera-segura" not in crudo


def test_entrar_no_delata_si_el_correo_existe(tmp_path):
    http = cliente(tmp_path)
    cuenta(http)
    ajena = http.post("/v1/sesion", json={"correo": "nadie@ejemplo.bo", "clave": "ribera-segura"})
    mala = http.post("/v1/sesion", json={"correo": "harold@ejemplo.bo", "clave": "clave-incorrecta"})
    assert ajena.status_code == mala.status_code == 401
    assert ajena.json()["error"]["mensaje"] == mala.json()["error"]["mensaje"] == MENSAJE_ENTRADA


def test_una_llave_revocada_y_la_de_otra_cuenta_no_entran(tmp_path):
    http = cliente(tmp_path)
    _cuenta, token = cuenta(http)
    mia = llave(http, token)
    sesion = {"Authorization": f"Bearer {token}"}
    apunte = http.post(
        "/v1/apuntes",
        json={"texto": "solo mío"},
        headers={"Authorization": f"Bearer {mia['secreto']}"},
    ).json()

    _otra, token_ajeno = cuenta(http, "otra@ejemplo.bo", "otra-clave-larga")
    ajena = llave(http, token_ajeno, "escritura", "ajena")
    ver = http.get("/v1/apuntes", headers={"Authorization": f"Bearer {ajena['secreto']}"})
    assert ver.json()["apuntes"] == []
    borrar = http.delete(
        f"/v1/apuntes/{apunte['id']}",
        headers={"Authorization": f"Bearer {ajena['secreto']}"},
    )
    assert borrar.status_code == 404
    assert http.get("/v1/apuntes", headers={"Authorization": f"Bearer {mia['secreto']}"}).json()["apuntes"]

    assert http.delete(f"/v1/llaves/{mia['id']}", headers=sesion).status_code == 204
    usada = http.get("/v1/apuntes", headers={"Authorization": f"Bearer {mia['secreto']}"})
    assert usada.status_code == 401
    assert usada.json()["error"]["mensaje"] == MENSAJE_LLAVE


def test_limite_cabeceras_y_cuerpo(tmp_path):
    http = cliente(tmp_path, limite=3)
    for _ in range(3):
        assert http.post("/v1/sesion", json={"correo": "a@b.co", "clave": "x"}).status_code == 401
    exceso = http.post("/v1/sesion", json={"correo": "a@b.co", "clave": "x"})
    assert exceso.status_code == 429
    assert exceso.headers["retry-after"] == "60"

    salud = http.get("/v1/salud")
    assert salud.json()["ok"] is True
    assert salud.headers["x-content-type-options"] == "nosniff"
    assert salud.headers["x-frame-options"] == "DENY"
    assert salud.headers["cache-control"] == "no-store"

    clave = "secreto-unico-xyz"
    invalida = http.post(
        "/v1/cuentas",
        json={"nombre": "Ana Ruiz", "correo": "no-es-correo", "clave": clave},
    )
    assert invalida.status_code == 422
    assert clave not in invalida.text

    grande = http.post("/v1/cuentas", content=b" " * 17000, headers={"content-type": "application/json"})
    assert grande.status_code == 413


def test_la_consulta_no_se_arma_con_el_correo(tmp_path):
    http = cliente(tmp_path)
    cuenta(http)
    ataque = http.post("/v1/sesion", json={"correo": "' OR 1=1 --", "clave": "ribera-segura"})
    assert ataque.status_code == 401
    filas = sqlite3.connect(tmp_path / "llavero.db").execute("SELECT COUNT(*) FROM cuentas").fetchone()[0]
    assert filas == 1


def test_el_contrato_esta_en_openapi(tmp_path):
    http = cliente(tmp_path)
    rutas = http.get("/openapi.json").json()["paths"]
    assert set(rutas) == {
        "/v1/salud",
        "/v1/cuentas",
        "/v1/sesion",
        "/v1/yo",
        "/v1/llaves",
        "/v1/llaves/{llave_id}",
        "/v1/apuntes",
        "/v1/apuntes/{apunte_id}",
    }
