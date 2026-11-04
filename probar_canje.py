"""Prueba rápida del servicio de activación de Make (sin abrir la app).

Uso (en la carpeta del proyecto, con tu .env configurado):
    python probar_canje.py                      # usa el código de prueba sembrado en Make
    python probar_canje.py CODIGO email@x.com   # prueba un código real

Comprueba: 1) que Make responde y la firma es válida, 2) que el mismo código en OTRO
equipo se rechaza. Ojo: ligar un código a este equipo lo "gasta" (para el código de prueba,
pídeme que lo reinicie o vacía el campo `machine` en el Data Store de Make).
"""
import secrets
import sys

import Gestor_contrasenas_secure as g

LAM = g.LicenseActivationManager
code, email = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ("ZZTEST12345678AB", "prueba@example.com")
wanted = LAM.code_hash(code, email)


def call(machine):
    nonce = secrets.token_hex(8)
    body = LAM._call_server({"v": 3, "code_hash": wanted, "machine": machine, "nonce": nonce})
    return body, nonce


try:
    machine = g.machine_id()
    body, nonce = call(machine)
    print("Respuesta equipo real :", body)
    if body.get("ok") is not True:
        sys.exit("FALLO: Make no aceptó el código (¿ya usado, o no existe en el Data Store?)")
    fields = {k: str(body.get(k, "")) for k in ("plan", "reference", "meses", "created_at")}
    expected = LAM.response_signature(wanted, machine, nonce, fields["plan"], fields["reference"],
                                      fields["meses"], fields["created_at"], g.ACTIVATION_SECRET)
    print("Firma válida          :", str(body.get("sig", "")).lower() == expected)
    other, _ = call("equipo-falso-" + secrets.token_hex(4))
    print("Otro equipo           :", other)
    ok = str(body.get("sig", "")).lower() == expected and other.get("error") == "used"
    print("\nRESULTADO:", "TODO BIEN ✅" if ok else "REVISAR ❌")
except g.ActivationError as exc:
    sys.exit(f"FALLO: {exc}")
