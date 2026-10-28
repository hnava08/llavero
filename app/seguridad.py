import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Optional

ITERACIONES = 200_000
HASH_FIJO = None  # se llena al importar, más abajo


def hash_clave(clave: str, sal: Optional[str] = None) -> str:
    sal = sal or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", clave.encode(), sal.encode(), ITERACIONES)
    return f"{sal}${dk.hex()}"


def clave_ok(clave: str, guardada: str) -> bool:
    sal, _, _firma = guardada.partition("$")
    return secrets.compare_digest(hash_clave(clave, sal), guardada)


HASH_FIJO = hash_clave("llavero-no-es-una-cuenta", sal="00" * 16)


def emitir_sesion(cuenta_id: str, secreto: str, ttl: int) -> tuple:
    expira = int(time.time()) + ttl
    cuerpo = json.dumps({"sub": cuenta_id, "exp": expira}, separators=(",", ":")).encode()
    carga = base64.urlsafe_b64encode(cuerpo).decode().rstrip("=")
    firma = hmac.new(secreto.encode(), carga.encode(), hashlib.sha256).hexdigest()
    return f"ses_{carga}.{firma}", expira


def leer_sesion(token: str, secreto: str) -> Optional[str]:
    if not token.startswith("ses_") or "." not in token:
        return None
    carga, _, firma = token[4:].partition(".")
    esperada = hmac.new(secreto.encode(), carga.encode(), hashlib.sha256).hexdigest()
    if not secrets.compare_digest(esperada, firma):
        return None
    relleno = "=" * (-len(carga) % 4)
    try:
        datos = json.loads(base64.urlsafe_b64decode(carga + relleno))
    except (json.JSONDecodeError, ValueError):
        return None
    if int(datos.get("exp", 0)) <= int(time.time()):
        return None
    sub = datos.get("sub")
    return str(sub) if sub else None


def nueva_llave() -> str:
    return "llv_" + secrets.token_urlsafe(32)


def prefijo_de(secreto: str) -> Optional[str]:
    if not secreto.startswith("llv_") or len(secreto) < 20:
        return None
    return secreto[:12]


def hash_llave(secreto: str) -> str:
    return hashlib.sha256(secreto.encode()).hexdigest()


class Limitador:
    def __init__(self, limite: int, ventana: int):
        self.limite = limite
        self.ventana = ventana
        self._marcas = {}
        self._lock = threading.Lock()

    def permitir(self, clave: str) -> bool:
        ahora = time.time()
        with self._lock:
            marcas = [t for t in self._marcas.get(clave, []) if ahora - t < self.ventana]
            if len(marcas) >= self.limite:
                self._marcas[clave] = marcas
                return False
            marcas.append(ahora)
            self._marcas[clave] = marcas
            return True
