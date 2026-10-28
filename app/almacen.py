import sqlite3
import uuid
from datetime import datetime, timezone


def ahora() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def conectar(ruta: str) -> sqlite3.Connection:
    conn = sqlite3.connect(ruta)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def iniciar(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cuentas (
          id TEXT PRIMARY KEY,
          nombre TEXT NOT NULL,
          correo TEXT NOT NULL UNIQUE,
          clave_hash TEXT NOT NULL,
          creada TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS llaves (
          id TEXT PRIMARY KEY,
          cuenta_id TEXT NOT NULL REFERENCES cuentas(id),
          nombre TEXT NOT NULL,
          alcance TEXT NOT NULL CHECK (alcance IN ('lectura', 'escritura')),
          prefijo TEXT NOT NULL UNIQUE,
          secreto_hash TEXT NOT NULL,
          creada TEXT NOT NULL,
          revocada TEXT
        );
        CREATE TABLE IF NOT EXISTS apuntes (
          id TEXT PRIMARY KEY,
          cuenta_id TEXT NOT NULL REFERENCES cuentas(id),
          texto TEXT NOT NULL,
          creada TEXT NOT NULL
        );
        """
    )


def crear_cuenta(conn, nombre: str, correo: str, clave_hash: str) -> dict:
    cuenta_id = str(uuid.uuid4())
    creada = ahora()
    conn.execute(
        "INSERT INTO cuentas (id, nombre, correo, clave_hash, creada) VALUES (?, ?, ?, ?, ?)",
        (cuenta_id, nombre, correo, clave_hash, creada),
    )
    return {"id": cuenta_id, "nombre": nombre, "correo": correo, "creada": creada}


def cuenta_por_correo(conn, correo: str):
    return conn.execute("SELECT * FROM cuentas WHERE correo = ?", (correo,)).fetchone()


def cuenta_por_id(conn, cuenta_id: str):
    return conn.execute("SELECT id, nombre, correo FROM cuentas WHERE id = ?", (cuenta_id,)).fetchone()


def crear_llave(conn, cuenta_id: str, nombre: str, alcance: str, prefijo: str, secreto_hash: str) -> dict:
    llave_id = str(uuid.uuid4())
    creada = ahora()
    conn.execute(
        """
        INSERT INTO llaves (id, cuenta_id, nombre, alcance, prefijo, secreto_hash, creada)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (llave_id, cuenta_id, nombre, alcance, prefijo, secreto_hash, creada),
    )
    return {
        "id": llave_id,
        "nombre": nombre,
        "alcance": alcance,
        "prefijo": prefijo,
        "creada": creada,
        "estado": "activa",
    }


def llaves_de(conn, cuenta_id: str) -> list:
    filas = conn.execute(
        """
        SELECT id, nombre, alcance, prefijo, creada, revocada
        FROM llaves WHERE cuenta_id = ? ORDER BY creada DESC
        """,
        (cuenta_id,),
    ).fetchall()
    return [
        {
            "id": fila["id"],
            "nombre": fila["nombre"],
            "alcance": fila["alcance"],
            "prefijo": fila["prefijo"],
            "creada": fila["creada"],
            "estado": "revocada" if fila["revocada"] else "activa",
        }
        for fila in filas
    ]


def llave_por_prefijo(conn, prefijo: str):
    return conn.execute("SELECT * FROM llaves WHERE prefijo = ?", (prefijo,)).fetchone()


def revocar_llave(conn, llave_id: str, cuenta_id: str) -> bool:
    cur = conn.execute(
        """
        UPDATE llaves SET revocada = ?
        WHERE id = ? AND cuenta_id = ? AND revocada IS NULL
        """,
        (ahora(), llave_id, cuenta_id),
    )
    return cur.rowcount == 1


def crear_apunte(conn, cuenta_id: str, texto: str) -> dict:
    apunte_id = str(uuid.uuid4())
    creada = ahora()
    conn.execute(
        "INSERT INTO apuntes (id, cuenta_id, texto, creada) VALUES (?, ?, ?, ?)",
        (apunte_id, cuenta_id, texto, creada),
    )
    return {"id": apunte_id, "texto": texto, "creada": creada}


def apuntes_de(conn, cuenta_id: str) -> list:
    filas = conn.execute(
        "SELECT id, texto, creada FROM apuntes WHERE cuenta_id = ? ORDER BY creada DESC",
        (cuenta_id,),
    ).fetchall()
    return [dict(fila) for fila in filas]


def borrar_apunte(conn, apunte_id: str, cuenta_id: str) -> bool:
    cur = conn.execute(
        "DELETE FROM apuntes WHERE id = ? AND cuenta_id = ?",
        (apunte_id, cuenta_id),
    )
    return cur.rowcount == 1
