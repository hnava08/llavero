import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Ajustes:
    db_path: str
    secreto: str
    limite: int
    ventana: int
    ttl: int


def desde_entorno() -> Ajustes:
    secreto = os.getenv("LLAVERO_SECRETO", "")
    if os.getenv("LLAVERO_ENTORNO") == "produccion" and len(secreto) < 16:
        raise RuntimeError("En producción hace falta LLAVERO_SECRETO.")
    if not secreto:
        secreto = "llavero-local"
    return Ajustes(
        db_path=os.getenv("LLAVERO_DB", "llavero.db"),
        secreto=secreto,
        limite=int(os.getenv("LLAVERO_LIMITE", "8")),
        ventana=int(os.getenv("LLAVERO_VENTANA", "60")),
        ttl=int(os.getenv("LLAVERO_TTL", "7200")),
    )
