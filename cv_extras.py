"""
cv_extras.py – Funciones de apoyo de CipherVault que no dependen de la interfaz.

  · Importar / exportar CSV (Chrome, Edge, Firefox, Bitwarden, LastPass, 1Password,
    KeePass/KeePassXC, Apple Passwords, Proton Pass y CSV genérico).
  · Códigos 2FA (TOTP, RFC 6238) sin dependencias externas.
  · Kit de emergencia en PDF (generador PDF mínimo, sin dependencias).
  · Auto-escritura con un atajo de teclado global (Windows, ctypes).
  · Desbloqueo con Windows Hello (Windows, paquetes winrt opcionales).

Todo lo específico de Windows se carga de forma perezosa: en otros sistemas, o si
faltan los paquetes, las funciones informan que no están disponibles en vez de fallar.

© 2026 S.C.A - CipherVault. Todos los derechos reservados. Software con licencia
comercial: queda prohibida su copia, distribución o modificación sin autorización
expresa del autor.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import logging
import os
import queue
import re
import struct
import sys
import threading
import unicodedata
import time
import urllib.parse
from datetime import datetime

log = logging.getLogger("ciphervault")


# ══════════════════════════════════════════════
#  CSV: IMPORTAR / EXPORTAR
# ══════════════════════════════════════════════
# Nombres de columna (en minúsculas) que usa cada gestor, agrupados por campo.
_CSV_ALIASES = {
    "service":  ("name", "title", "nombre", "servicio", "account", "website name", "item name"),
    "url":      ("url", "login_uri", "website", "web site", "uri", "urls", "sitio", "sitio web", "login url"),
    "username": ("username", "login_username", "user", "user name", "login", "login name", "usuario",
                 "email", "e-mail", "correo"),
    "password": ("password", "login_password", "pass", "contraseña", "contrasena", "clave"),
    "notes":    ("note", "notes", "extra", "comments", "comment", "nota", "notas"),
    "totp":     ("totp", "login_totp", "otpauth", "otp", "one-time password", "2fa", "authenticator"),
    "category": ("folder", "grouping", "group", "category", "categoría", "categoria", "vault"),
    "type":     ("type",),
}

CSV_EXPORT_HEADER = ["name", "url", "username", "password", "note", "totp", "category"]
MAX_CSV_BYTES = 20 * 1024 * 1024


def decode_csv_bytes(raw: bytes) -> str:
    """Decodifica un CSV exportado por un navegador u otro gestor (UTF-8 con o sin BOM,
    o Windows-1252 si viene de Excel)."""
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def _host_from_url(url: str) -> str:
    """'https://www.facebook.com/login' → 'facebook.com'."""
    url = (url or "").strip()
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def parse_password_csv(text: str) -> tuple[list[dict], int]:
    """
    Lee un CSV de contraseñas y devuelve (registros, filas_omitidas).
    Cada registro: {service, url, username, password, notes, totp, category}.
    Se omiten filas sin contraseña, notas seguras de LastPass y elementos de Bitwarden
    que no son inicios de sesión. Lanza ValueError si el archivo no tiene una columna
    de contraseña reconocible.
    """
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    try:
        header = next(reader)
    except StopIteration:
        raise ValueError("El archivo está vacío.") from None
    header = [h.strip().lstrip("﻿").lower() for h in header]

    index: dict[str, int] = {}
    for field, aliases in _CSV_ALIASES.items():
        for alias in aliases:
            if alias in header:
                index[field] = header.index(alias)
                break
    if "password" not in index:
        raise ValueError("No se encontró una columna de contraseñas. Exporta el CSV desde tu navegador "
                         "o gestor (debe tener una columna «password»).")

    def cell(row: list[str], field: str) -> str:
        pos = index.get(field)
        return row[pos].strip() if pos is not None and pos < len(row) and row[pos] is not None else ""

    records, skipped = [], 0
    for row in reader:
        if not any((c or "").strip() for c in row):
            continue
        kind = cell(row, "type").lower()
        if kind and kind not in ("login", "1", "password"):
            skipped += 1                      # Bitwarden: notas, tarjetas, identidades
            continue
        url = cell(row, "url")
        if url.lower() == "http://sn":        # LastPass: nota segura
            skipped += 1
            continue
        password = row[index["password"]] if index["password"] < len(row) else ""
        if not password:
            skipped += 1
            continue
        username = cell(row, "username")
        service = cell(row, "service") or _host_from_url(url) or username or "Sin nombre"
        category = cell(row, "category")
        if category.lower() in ("root", "raíz", "raiz", "personal vault", "/"):
            category = ""
        records.append({
            "service": service[:200],
            "url": url[:500],
            "username": username[:200],
            "password": password,
            "notes": cell(row, "notes"),
            "totp": cell(row, "totp"),
            "category": (category.split("/")[-1].strip() or "General")[:40],
        })
    return records, skipped


def records_to_csv(records: list[dict]) -> str:
    """CSV compatible con Chrome/Edge (name,url,username,password,note) más totp y categoría."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_EXPORT_HEADER)
    for rec in records:
        writer.writerow([rec.get("service", ""), rec.get("url", ""), rec.get("username", ""),
                         rec.get("password", ""), rec.get("notes", ""), rec.get("totp", ""),
                         rec.get("category", "")])
    return out.getvalue()


# ══════════════════════════════════════════════
#  CÓDIGOS 2FA (TOTP, RFC 6238)
# ══════════════════════════════════════════════
_TOTP_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def _b32decode(secret: str) -> bytes:
    clean = re.sub(r"[\s\-]", "", secret or "").upper().rstrip("=")
    if not clean or not re.fullmatch(r"[A-Z2-7]+", clean):
        raise ValueError("La clave 2FA no es válida (debe ser Base32: letras A-Z y números 2-7).")
    padded = clean + "=" * (-len(clean) % 8)
    try:
        key = base64.b32decode(padded)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("La clave 2FA no es válida.") from exc
    if len(key) < 10:
        raise ValueError("La clave 2FA es demasiado corta.")
    return key


def parse_totp(text: str) -> dict:
    """
    Acepta una clave Base32 («JBSW Y3DP EHPK 3PXP») o un enlace otpauth://totp/...
    Devuelve {secret, digits, period, algorithm, issuer, label}; lanza ValueError si no sirve.
    """
    text = (text or "").strip()
    cfg = {"digits": 6, "period": 30, "algorithm": "SHA1", "issuer": "", "label": ""}
    if text.lower().startswith("otpauth://"):
        parts = urllib.parse.urlsplit(text)
        if parts.netloc.lower() != "totp":
            raise ValueError("Solo se admiten códigos TOTP (otpauth://totp/...).")
        query = dict(urllib.parse.parse_qsl(parts.query))
        cfg["label"] = urllib.parse.unquote(parts.path.lstrip("/"))
        cfg["issuer"] = query.get("issuer", "")
        secret = query.get("secret", "")
        if query.get("digits", "").isdigit():
            cfg["digits"] = int(query["digits"])
        if query.get("period", "").isdigit():
            cfg["period"] = int(query["period"])
        cfg["algorithm"] = query.get("algorithm", "SHA1").upper()
    else:
        secret = text
    if cfg["algorithm"] not in _TOTP_ALGOS:
        raise ValueError(f"Algoritmo 2FA no soportado: {cfg['algorithm']}")
    if cfg["digits"] not in (6, 7, 8) or not 10 <= cfg["period"] <= 120:
        raise ValueError("La configuración del código 2FA no es válida.")
    _b32decode(secret)
    cfg["secret"] = re.sub(r"[\s\-]", "", secret).upper().rstrip("=")
    return cfg


def totp_code(text_or_cfg, at: float | None = None) -> tuple[str, int]:
    """Código TOTP actual y segundos que le quedan."""
    cfg = parse_totp(text_or_cfg) if isinstance(text_or_cfg, str) else text_or_cfg
    key = _b32decode(cfg["secret"])
    now = time.time() if at is None else at
    counter = int(now // cfg["period"])
    digest = hmac.new(key, struct.pack(">Q", counter), _TOTP_ALGOS[cfg["algorithm"]]).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** cfg["digits"])
    remaining = cfg["period"] - int(now % cfg["period"])
    return str(value).zfill(cfg["digits"]), remaining


# ══════════════════════════════════════════════
#  VERIFICACIÓN EN DOS PASOS AL INICIAR SESIÓN (Premium y Equipo)
# ══════════════════════════════════════════════
# La clave TOTP se guarda cifrada con la bóveda (sin la contraseña maestra no se puede leer)
# y los códigos de respaldo solo como hash. Se acepta el código de la ventana actual y el de
# las ventanas vecinas (±30 s por relojes desfasados), y nunca dos veces el mismo.
_BACKUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"     # sin 0/O ni 1/I


def new_login_secret() -> str:
    """Clave Base32 de 160 bits (lo que usan Google Authenticator y similares)."""
    import secrets
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def login_totp_uri(secret: str, account: str, issuer: str = "CipherVault") -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    query = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "digits": 6, "period": 30})
    return f"otpauth://totp/{label}?{query}"


def group_secret(secret: str) -> str:
    """'JBSWY3DPEHPK3PXP' → 'JBSW Y3DP EHPK 3PXP' (más fácil de copiar a mano)."""
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


def verify_login_totp(secret: str, code: str, last_counter: int | None = None,
                      at: float | None = None, window: int = 1) -> int | None:
    """Si `code` es válido devuelve el contador de 30 s que usó (para no aceptarlo otra vez);
    si no, None. Rechaza contadores menores o iguales a `last_counter`."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    cfg = {"secret": secret, "digits": 6, "period": 30, "algorithm": "SHA1"}
    now = time.time() if at is None else at
    base = int(now // 30)
    for counter in range(base - window, base + window + 1):
        if last_counter is not None and counter <= last_counter:
            continue
        expected, _ = totp_code(cfg, at=counter * 30)
        if hmac.compare_digest(expected, code):
            return counter
    return None


def new_backup_codes(count: int = 8) -> list[str]:
    """Códigos de un solo uso para entrar si se pierde el celular: 'K7QF-M2XR'."""
    import secrets
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def normalize_backup_code(code: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


def hash_backup_code(user_id: int, code: str) -> str:
    return hashlib.sha256(f"cv-backup|{user_id}|{normalize_backup_code(code)}".encode("utf-8")).hexdigest()


def qr_matrix(text: str) -> list[list[bool]]:
    """Matriz del código QR (True = módulo oscuro), sin el margen. Usa `segno`."""
    import segno
    qr = segno.make(text, error="m", micro=False)
    return [[bool(cell) for cell in row] for row in qr.matrix]


# ══════════════════════════════════════════════
#  KIT DE EMERGENCIA (PDF mínimo, sin dependencias)
# ══════════════════════════════════════════════
def _pdf_text(value: str) -> str:
    raw = value.encode("cp1252", "replace").decode("latin-1")
    return raw.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(text: str, width: int) -> list[str]:
    words, lines, line = text.split(), [], ""
    for word in words:
        if len(line) + len(word) + (1 if line else 0) > width:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    if line:
        lines.append(line)
    return lines or [""]


def build_emergency_kit_pdf(username: str, email: str, data_folder: str,
                            support_email: str, app_version: str,
                            created: datetime | None = None) -> bytes:
    """Genera el PDF del kit de emergencia. NUNCA incluye la contraseña maestra: deja un
    recuadro para escribirla a mano."""
    created = created or datetime.now()
    ops: list[str] = []
    y = 790

    def text(x, size, value, bold=False, gray=False):
        font = "F2" if bold else "F1"
        color = "0.35 0.35 0.35 rg" if gray else "0 0 0 rg"
        ops.append(f"BT {color} /{font} {size} Tf {x} {y} Td ({_pdf_text(value)}) Tj ET")

    def para(value, size=10, width=95, bold=False, gap=4):
        nonlocal y
        for line in _wrap(value, width):
            text(56, size, line, bold=bold)
            y -= size + gap

    # encabezado
    ops.append("0.42 0.36 0.91 rg 0 800 595 42 re f")
    ops.append(f"BT 1 1 1 rg /F2 18 Tf 56 814 Td ({_pdf_text('CipherVault - Kit de emergencia')}) Tj ET")
    y = 770
    text(56, 9, f"Creado el {created:%d/%m/%Y %H:%M} - versión {app_version}", gray=True)
    y -= 26

    para("Imprime esta hoja, escribe tu contraseña maestra a mano y guárdala en un lugar seguro "
         "(por ejemplo, con tus documentos importantes). No la guardes como foto ni en la nube.")
    y -= 10

    rows = [("Usuario de CipherVault", username), ("Email de la cuenta", email or "-"),
            ("Carpeta de tus datos", data_folder)]
    for label, value in rows:
        text(56, 10, label, bold=True)
        text(220, 10, value)
        y -= 18
    y -= 8

    text(56, 11, "Contraseña maestra (escríbela a mano):", bold=True)
    y -= 12
    ops.append(f"0 0 0 RG 1 w 56 {y - 34} 500 38 re S")
    y -= 62

    para("Lo que debes saber", size=12, bold=True)
    for item in (
        "Si olvidas tu contraseña maestra, NADIE puede recuperar tus contraseñas, ni siquiera "
        "el soporte de CipherVault: así funciona el cifrado que las protege.",
        "Tus datos viven solo en este equipo, en la carpeta indicada arriba. Si cambias de PC, "
        "usa «Exportar bóveda» (.cvault) y luego «Importar» en el equipo nuevo.",
        "Haz una exportación .cvault de vez en cuando y guárdala en una memoria USB. Anota "
        "también la contraseña de esa exportación.",
        "La licencia se activa con el código que llega a tu email y sirve hasta en 3 de tus "
        "equipos. Si cambias de computador y ya usaste los 3, escribe a soporte.",
    ):
        lines = _wrap(item, 88)
        text(60, 10, "-")
        for line in lines:
            text(72, 10, line)
            y -= 14
        y -= 4
    y -= 10
    text(56, 10, "Contraseña de la última exportación .cvault:", bold=True)
    y -= 12
    ops.append(f"0 0 0 RG 1 w 56 {y - 30} 500 34 re S")
    y -= 56
    text(56, 9, f"Soporte: {support_email}", gray=True)
    y -= 14
    text(56, 9, "CipherVault - S.C.A. Este documento no contiene ninguna contraseña.", gray=True)

    stream = "\n".join(ops).encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


# ══════════════════════════════════════════════
#  AUTO-ESCRITURA (atajo global: Windows y macOS)
# ══════════════════════════════════════════════
# Cómo se reconoce el sitio:
#   1. Si la ventana activa es un navegador, se lee la DIRECCIÓN de la pestaña (Windows: UI
#      Automation sobre la barra de direcciones; Mac: AppleScript) y se compara su dominio con
#      la página web guardada (o, si la entrada no tiene página, con el nombre del servicio).
#      Una página falsa con el mismo título (phishing) no coincide.
#   2. Si no es un navegador, o no se pudo leer la dirección (p. ej. Firefox en Mac), se usa el
#      título de la ventana, como antes.
IS_MAC = sys.platform == "darwin"
AUTOTYPE_HOTKEY_LABEL = "Ctrl + Option + A" if IS_MAC else "Ctrl + Alt + A"
_GENERIC_TITLE_WORDS = {"google", "chrome", "edge", "firefox", "opera", "brave", "microsoft",
                        "mozilla", "inicio", "login", "sign", "iniciar", "sesión", "sesion", "nueva", "pestaña",
                        "safari", "vivaldi", "arc"}
# Sufijos de segundo nivel habituales: 'banco.com.co' → dominio registrable 'banco.com.co'.
_SECOND_LEVEL = {"com", "co", "gov", "gob", "edu", "org", "net", "ac", "mil", "nom", "or", "ne"}


def _norm(text: str) -> str:
    """Minúsculas, sin tildes ni espacios/símbolos: 'Mercado Libre' → 'mercadolibre'."""
    text = unicodedata.normalize("NFKD", (text or "").lower())
    return "".join(ch for ch in text if ch.isalnum() and not unicodedata.combining(ch))


def registrable_domain(host: str) -> str:
    """'mail.google.com' → 'google.com'; 'svp.bancolombia.com.co' → 'bancolombia.com.co'."""
    labels = [p for p in (host or "").lower().strip(".").split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _page_host(url: str) -> str:
    """Host de lo que muestra la barra de direcciones, o '' si no parece una dirección
    (texto de búsqueda, página interna del navegador...)."""
    url = (url or "").strip()
    if not url or " " in url or url.lower().startswith(("chrome:", "edge:", "about:", "brave:", "file:",
                                                         "view-source:", "opera:", "vivaldi:")):
        return ""
    host = _host_from_url(url)
    return host if host and "." in host and not host.startswith(".") else ""


def _entry_keywords(service: str, url: str) -> list[str]:
    """Palabras con las que una entrada se reconoce en el título de una ventana."""
    words = set()
    service = (service or "").strip().lower()
    if len(service) >= 3:
        words.add(service)
        host = _host_from_url(service) if "." in service else ""
        if host:
            words.add(host)
    host = _host_from_url(url)
    if host:
        words.add(host)
        base = registrable_domain(host).split(".")
        if base and len(base[0]) >= 3:
            words.add(base[0])           # 'mail.google.com' → 'google'; 'bancolombia.com.co' → 'bancolombia'
    return [w for w in words if len(w) >= 3 and w not in _GENERIC_TITLE_WORDS]


def match_entries(window_title: str, entries: list[dict]) -> list[dict]:
    """Por TÍTULO de ventana (programas que no son navegador): entradas cuya palabra clave
    aparece en el título, de la coincidencia más larga a la más corta. No distingue
    mayúsculas, tildes ni espacios ('MercadoLibre' encuentra 'Mercado Libre')."""
    title = (window_title or "").lower()
    if not title:
        return []
    flat = _norm(title)
    scored = []
    for entry in entries:
        best = 0
        for k in _entry_keywords(entry.get("service", ""), entry.get("url", "")):
            nk = _norm(k)
            if k in title or (len(nk) >= 3 and nk in flat):
                best = max(best, len(k))
        if best:
            scored.append((best, entry))
    scored.sort(key=lambda pair: -pair[0])
    return [entry for _, entry in scored]


def match_entries_by_url(page_url: str, entries: list[dict]) -> list[dict]:
    """Por DIRECCIÓN de la página (navegadores). Puntaje: mismo host (3) > mismo dominio
    (2) > el nombre del servicio es el del dominio, p. ej. 'Netflix' en netflix.com (1)."""
    host = _page_host(page_url)
    if not host:
        return []
    base = registrable_domain(host)
    name = _norm(base.split(".")[0])
    scored = []
    for entry in entries:
        score = 0
        saved = _page_host(entry.get("url", ""))
        service = (entry.get("service") or "").strip()
        if not saved and "." in service and " " not in service:
            saved = _page_host(service)               # servicio escrito como dominio: 'netflix.com'
        if saved:
            if saved == host:
                score = 3
            elif registrable_domain(saved) == base:
                score = 2
        elif len(name) >= 3:
            svc = _norm(service.split("(")[0])
            if svc == name or (len(name) >= 4 and svc.startswith(name)):
                score = 1
        if score:
            scored.append((score, entry))
    scored.sort(key=lambda pair: -pair[0])
    return [entry for _, entry in scored]


def autotype_supported() -> bool:
    if os.name == "nt":
        return True
    if IS_MAC:
        try:
            import AppKit  # noqa: F401
            import Quartz  # noqa: F401
            return True
        except ImportError:
            return False
    return False


# ── Windows ────────────────────────────────────────────────
_WIN_BROWSERS = {"chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "opera_gx.exe", "vivaldi.exe",
                 "firefox.exe", "arc.exe", "chromium.exe"}

if os.name == "nt":                       # pragma: no cover - solo Windows
    import ctypes
    from ctypes import wintypes

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _MOD_ALT, _MOD_CONTROL, _MOD_NOREPEAT = 0x0001, 0x0002, 0x4000
    _WM_HOTKEY, _WM_QUIT = 0x0312, 0x0012
    _VK_A, _VK_TAB, _VK_RETURN = 0x41, 0x09, 0x0D
    _VK_SHIFT, _VK_CONTROL, _VK_MENU, _VK_LWIN, _VK_RWIN = 0x10, 0x11, 0x12, 0x5B, 0x5C
    _INPUT_KEYBOARD, _KEYEVENTF_KEYUP, _KEYEVENTF_UNICODE = 1, 0x0002, 0x0004

    class _KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]

    class _MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]

    class _INPUTUNION(ctypes.Union):
        _fields_ = [("ki", _KEYBDINPUT), ("mi", _MOUSEINPUT)]

    class _INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]

    _user32.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(_INPUT), ctypes.c_int)
    _user32.GetForegroundWindow.restype = wintypes.HWND
    _user32.GetWindowTextLengthW.argtypes = (wintypes.HWND,)
    _user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    _user32.SetForegroundWindow.argtypes = (wintypes.HWND,)
    _user32.RegisterHotKey.argtypes = (wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT)
    _user32.UnregisterHotKey.argtypes = (wintypes.HWND, ctypes.c_int)
    _user32.GetMessageW.argtypes = (ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT)
    _user32.PostThreadMessageW.argtypes = (wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
    _user32.GetAsyncKeyState.argtypes = (ctypes.c_int,)
    _user32.GetAsyncKeyState.restype = ctypes.c_short
    _user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                     ctypes.POINTER(wintypes.DWORD))
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)


def _win_process_name(hwnd: int) -> str:     # pragma: no cover - solo Windows
    """'chrome.exe' para la ventana `hwnd` (minúsculas), o ''."""
    pid = wintypes.DWORD()
    _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    handle = _kernel32.OpenProcess(0x1000, False, pid.value)    # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        if not _kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return ""
        return os.path.basename(buf.value).lower()
    finally:
        _kernel32.CloseHandle(handle)


_UIA_CACHE: list = []


def _uia():                                   # pragma: no cover - solo Windows
    """(IUIAutomation, módulo generado) de UI Automation, creado una sola vez."""
    if not _UIA_CACHE:
        import comtypes.client
        mod = comtypes.client.GetModule("UIAutomationCore.dll")
        auto = comtypes.client.CreateObject(mod.CUIAutomation, interface=mod.IUIAutomation)
        _UIA_CACHE.extend([auto, mod])
    return _UIA_CACHE[0], _UIA_CACHE[1]


def _win_browser_url(hwnd: int, exe: str) -> str:    # pragma: no cover - solo Windows
    """Texto de la barra de direcciones de Chrome/Edge/Brave/Opera/Vivaldi/Firefox."""
    auto, mod = _uia()
    root = auto.ElementFromHandle(hwnd)
    if exe == "firefox.exe":
        cond = auto.CreatePropertyCondition(mod.UIA_AutomationIdPropertyId, "urlbar-input")
    else:                                     # Chromium: el primer cuadro de texto es la barra
        cond = auto.CreatePropertyCondition(mod.UIA_ControlTypePropertyId, mod.UIA_EditControlTypeId)
    element = root.FindFirst(mod.TreeScope_Descendants, cond)
    if not element:
        return ""
    pattern = element.GetCurrentPattern(mod.UIA_ValuePatternId)
    if not pattern:
        return ""
    return pattern.QueryInterface(mod.IUIAutomationValuePattern).CurrentValue or ""


# ── macOS ──────────────────────────────────────────────────
# AppleScript por navegador (Firefox no lo permite: ahí se usa el título).
_MAC_SAFARI = {"com.apple.safari", "com.apple.safaritechnologypreview"}
_MAC_CHROMIUM = {"com.google.chrome", "com.google.chrome.beta", "com.microsoft.edgemac", "com.brave.browser",
                 "com.vivaldi.vivaldi", "com.operasoftware.opera", "company.thebrowser.browser",
                 "org.chromium.chromium"}
_MAC_OTHER_BROWSERS = {"org.mozilla.firefox", "org.mozilla.firefoxdeveloperedition", "app.zen-browser.zen"}
_MAC_APP_IDS: dict[int, str] = {}             # pid → bundle id (lo llena el atajo)


def _mac_bundle_id(pid: int) -> str:          # pragma: no cover - solo macOS
    if pid in _MAC_APP_IDS:
        return _MAC_APP_IDS[pid]
    try:
        import AppKit
        app = AppKit.NSRunningApplication.runningApplicationWithProcessIdentifier_(pid)
        return (str(app.bundleIdentifier() or "") if app else "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _mac_browser_url(bundle_id: str) -> str:  # pragma: no cover - solo macOS
    if bundle_id in _MAC_SAFARI:
        script = f'tell application id "{bundle_id}" to get URL of front document'
    elif bundle_id in _MAC_CHROMIUM:
        script = f'tell application id "{bundle_id}" to get URL of active tab of front window'
    else:
        return ""
    import subprocess
    result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=3)
    if result.returncode != 0:
        log.info("Auto-escritura: AppleScript no pudo leer la dirección (%s)", result.stderr.strip()[:200])
        return ""
    return result.stdout.strip()


def mac_accessibility_trusted() -> bool:      # pragma: no cover - solo macOS
    """¿Tiene CipherVault permiso de Accesibilidad (necesario para el atajo y para escribir)?"""
    if not IS_MAC:
        return False
    try:
        import ctypes
        lib = ctypes.cdll.LoadLibrary(
            "/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
        lib.AXIsProcessTrusted.restype = ctypes.c_bool
        return bool(lib.AXIsProcessTrusted())
    except OSError:
        return False


def open_mac_accessibility_settings():        # pragma: no cover - solo macOS
    import subprocess
    subprocess.Popen(["open", "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"])


# ── común ──────────────────────────────────────────────────
def is_browser_window(handle: int) -> bool:
    """¿La ventana (Windows: hwnd; Mac: pid de la app) es de un navegador?"""
    try:
        if os.name == "nt":
            return _win_process_name(handle) in _WIN_BROWSERS
        if IS_MAC:
            bid = _mac_bundle_id(handle)
            return bid in _MAC_SAFARI or bid in _MAC_CHROMIUM or bid in _MAC_OTHER_BROWSERS
    except Exception as exc:  # noqa: BLE001
        log.info("Auto-escritura: no se pudo identificar el programa (%s)", exc)
    return False


def browser_url(handle: int) -> str:
    """Dirección de la pestaña activa del navegador, o '' si no se puede leer."""
    try:
        if os.name == "nt":
            return _win_browser_url(handle, _win_process_name(handle))
        if IS_MAC:
            return _mac_browser_url(_mac_bundle_id(handle))
    except Exception as exc:  # noqa: BLE001  (sin comtypes, sin permiso, navegador cerrándose...)
        log.info("Auto-escritura: no se pudo leer la dirección del navegador (%s)", exc)
    return ""


def foreground_window() -> tuple[int, str]:
    """(handle, título) de la ventana que tiene el foco. En Mac el handle es el pid."""
    if os.name == "nt":
        hwnd = _user32.GetForegroundWindow()
        length = _user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        _user32.GetWindowTextW(hwnd, buf, length + 1)
        return int(hwnd or 0), buf.value
    if IS_MAC:                                # pragma: no cover - solo macOS
        try:
            import AppKit
            import Quartz
            app = AppKit.NSWorkspace.sharedWorkspace().frontmostApplication()
            pid = int(app.processIdentifier())
            _MAC_APP_IDS[pid] = str(app.bundleIdentifier() or "").lower()
            title = ""
            windows = Quartz.CGWindowListCopyWindowInfo(
                Quartz.kCGWindowListOptionOnScreenOnly | Quartz.kCGWindowListExcludeDesktopElements,
                Quartz.kCGNullWindowID) or []
            for info in windows:
                if int(info.get("kCGWindowOwnerPID", -1)) == pid and int(info.get("kCGWindowLayer", 1)) == 0:
                    title = str(info.get("kCGWindowName") or "")
                    break
            return pid, f"{title} - {app.localizedName()}" if title else str(app.localizedName() or "")
        except Exception as exc:  # noqa: BLE001
            log.info("Auto-escritura: no se pudo leer la ventana activa (%s)", exc)
    return 0, ""


def focus_window(handle: int) -> bool:
    if not handle:
        return False
    if os.name == "nt":
        return bool(_user32.SetForegroundWindow(handle))
    if IS_MAC:                                # pragma: no cover - solo macOS
        try:
            import AppKit
            app = AppKit.NSRunningApplication.runningApplicationWithProcessIdentifier_(handle)
            if app:
                app.activateWithOptions_(AppKit.NSApplicationActivateIgnoringOtherApps)
                time.sleep(0.25)
                return True
        except Exception:  # noqa: BLE001
            return False
    return False


def _wait_modifiers_released(timeout: float = 3.0):
    """Espera a que el usuario suelte Ctrl/Alt(Option)/Shift/Win(Cmd); si no, el texto se
    escribiría como atajos de teclado."""
    end = time.monotonic() + timeout
    if os.name == "nt":
        keys = (_VK_SHIFT, _VK_CONTROL, _VK_MENU, _VK_LWIN, _VK_RWIN)
        pressed = lambda: any(_user32.GetAsyncKeyState(k) & 0x8000 for k in keys)  # noqa: E731
    else:                                     # pragma: no cover - solo macOS
        import Quartz
        mask = (Quartz.kCGEventFlagMaskShift | Quartz.kCGEventFlagMaskControl |
                Quartz.kCGEventFlagMaskAlternate | Quartz.kCGEventFlagMaskCommand)
        pressed = lambda: bool(Quartz.CGEventSourceFlagsState(  # noqa: E731
            Quartz.kCGEventSourceStateCombinedSessionState) & mask)
    while time.monotonic() < end:
        if not pressed():
            return
        time.sleep(0.03)


def _send(inputs: list) -> None:
    arr = (_INPUT * len(inputs))(*inputs)
    sent = _user32.SendInput(len(inputs), arr, ctypes.sizeof(_INPUT))
    if sent != len(inputs):
        raise OSError(ctypes.get_last_error(), "SendInput bloqueado")


def _key(vk: int) -> list:
    return [_INPUT(_INPUT_KEYBOARD, _INPUTUNION(ki=_KEYBDINPUT(vk, 0, 0, 0, 0))),
            _INPUT(_INPUT_KEYBOARD, _INPUTUNION(ki=_KEYBDINPUT(vk, 0, _KEYEVENTF_KEYUP, 0, 0)))]


def _unicode(text: str) -> list:
    inputs = []
    data = text.encode("utf-16-le")
    for i in range(0, len(data), 2):
        unit = int.from_bytes(data[i:i + 2], "little")
        inputs.append(_INPUT(_INPUT_KEYBOARD, _INPUTUNION(ki=_KEYBDINPUT(0, unit, _KEYEVENTF_UNICODE, 0, 0))))
        inputs.append(_INPUT(_INPUT_KEYBOARD, _INPUTUNION(
            ki=_KEYBDINPUT(0, unit, _KEYEVENTF_UNICODE | _KEYEVENTF_KEYUP, 0, 0))))
    return inputs


def _mac_post_key(keycode: int = 0, text: str = "") -> None:   # pragma: no cover - solo macOS
    import Quartz
    for down in (True, False):
        event = Quartz.CGEventCreateKeyboardEvent(None, keycode, down)
        Quartz.CGEventSetFlags(event, 0)      # sin Ctrl/Option heredados del atajo
        if text:
            Quartz.CGEventKeyboardSetUnicodeString(event, len(text.encode("utf-16-le")) // 2, text)
        Quartz.CGEventPost(Quartz.kCGHIDEventTap, event)
    time.sleep(0.008)


def type_login(username: str, password: str, press_enter: bool = False) -> None:
    """Escribe usuario, TAB y contraseña en la ventana activa (y Enter si se pide)."""
    if os.name == "nt":
        _wait_modifiers_released()
        time.sleep(0.05)
        if username:
            _send(_unicode(username))
            _send(_key(_VK_TAB))
        _send(_unicode(password))
        if press_enter:
            _send(_key(_VK_RETURN))
        return
    if IS_MAC:                                # pragma: no cover - solo macOS
        if not mac_accessibility_trusted():
            raise PermissionError("Falta el permiso de Accesibilidad.")
        _wait_modifiers_released()
        time.sleep(0.05)
        if username:
            for ch in username:
                _mac_post_key(text=ch)
            _mac_post_key(48)                 # Tab
        for ch in password:
            _mac_post_key(text=ch)
        if press_enter:
            _mac_post_key(36)                 # Return
        return
    raise OSError("La auto-escritura solo funciona en Windows y macOS.")


class HotkeyListener:
    """Atajo global (Ctrl+Alt+A en Windows, Ctrl+Option+A en Mac). Cuando se pulsa guarda en
    una cola (handle, título) de la ventana activa; la interfaz la lee con poll() desde el hilo
    de Tk. Windows: RegisterHotKey en un hilo propio. Mac: monitor global de NSEvent en el hilo
    principal (el bucle de Tk es el de Cocoa); necesita permiso de Accesibilidad."""
    HOTKEY_ID = 0xC1F0

    def __init__(self):
        self.events: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None
        self._thread_id = 0
        self._ready = threading.Event()
        self._monitor = None
        self.error = ""

    @property
    def running(self) -> bool:
        if IS_MAC:
            return self._monitor is not None and not self.error
        return bool(self._thread and self._thread.is_alive() and not self.error)

    def start(self) -> bool:
        if IS_MAC:
            return self._start_mac()
        if os.name != "nt":
            self.error = "Solo disponible en Windows y macOS."
            return False
        if self.running:
            return True
        self.error = ""
        self._ready.clear()
        self._thread = threading.Thread(target=self._run, name="cv-hotkey", daemon=True)
        self._thread.start()
        self._ready.wait(2)
        return self.running

    def _start_mac(self) -> bool:             # pragma: no cover - solo macOS
        if self._monitor is not None:
            self.error = "" if mac_accessibility_trusted() else self.error
            return True
        try:
            import AppKit
        except ImportError:
            self.error = "Falta el componente de macOS (pyobjc) en esta instalación."
            return False
        self.error = "" if mac_accessibility_trusted() else (
            "Falta el permiso de Accesibilidad: Ajustes del Sistema → Privacidad y seguridad → "
            "Accesibilidad → activa CipherVault y vuelve a abrir la app.")
        wanted = AppKit.NSEventModifierFlagControl | AppKit.NSEventModifierFlagOption
        others = AppKit.NSEventModifierFlagCommand | AppKit.NSEventModifierFlagShift

        def handler(event):
            try:
                flags = int(event.modifierFlags())
                key = str(event.charactersIgnoringModifiers() or "").lower()
                if (flags & wanted) == wanted and not (flags & others) and (key == "a" or event.keyCode() == 0):
                    self.events.put(foreground_window())
            except Exception as exc:  # noqa: BLE001
                log.warning("Auto-escritura: error en el atajo (%s)", exc)
        self._handler = handler               # el bloque debe seguir vivo
        self._monitor = AppKit.NSEvent.addGlobalMonitorForEventsMatchingMask_handler_(
            AppKit.NSEventMaskKeyDown, handler)
        return self._monitor is not None

    def _run(self):                                       # pragma: no cover - solo Windows
        self._thread_id = _kernel32.GetCurrentThreadId()
        if not _user32.RegisterHotKey(None, self.HOTKEY_ID, _MOD_CONTROL | _MOD_ALT | _MOD_NOREPEAT, _VK_A):
            self.error = (f"No se pudo registrar el atajo {AUTOTYPE_HOTKEY_LABEL}: otro programa ya lo usa.")
            log.warning("Auto-escritura: RegisterHotKey falló (%s)", ctypes.get_last_error())
            self._ready.set()
            return
        self._ready.set()
        msg = wintypes.MSG()
        try:
            while _user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                if msg.message == _WM_HOTKEY and msg.wParam == self.HOTKEY_ID:
                    self.events.put(foreground_window())
        finally:
            _user32.UnregisterHotKey(None, self.HOTKEY_ID)

    def stop(self):
        if IS_MAC:
            if self._monitor is not None:     # pragma: no cover - solo macOS
                import AppKit
                AppKit.NSEvent.removeMonitor_(self._monitor)
            self._monitor = None
            return
        if os.name == "nt" and self._thread and self._thread.is_alive() and self._thread_id:
            _user32.PostThreadMessageW(self._thread_id, _WM_QUIT, 0, 0)
            self._thread.join(1)
        self._thread = None

    def poll(self) -> tuple[int, str] | None:
        try:
            return self.events.get_nowait()
        except queue.Empty:
            return None


# ══════════════════════════════════════════════
#  WINDOWS HELLO
# ══════════════════════════════════════════════
# Diseño (el mismo que usa KeePassXC): Windows Hello guarda una clave RSA en el TPM del
# equipo, protegida por la huella / rostro / PIN. Firmar un "reto" aleatorio con esa clave
# da siempre la misma firma (RSA PKCS#1 v1.5), y de su SHA-256 sale una clave que cifra la
# clave de la bóveda. Sin Windows Hello (o en otro equipo) la firma no se puede obtener.
# Además el resultado se protege con DPAPI, que lo ata a la cuenta de Windows.

class HelloError(Exception):
    pass


def _winrt():
    """Importa los módulos WinRT necesarios o lanza HelloError."""
    if os.name != "nt":
        raise HelloError("Windows Hello solo está disponible en Windows.")
    try:
        from winrt.windows.security.credentials import (KeyCredentialManager,  # noqa: F401
                                                        KeyCredentialCreationOption, KeyCredentialStatus)
        from winrt.windows.security.cryptography import CryptographicBuffer  # noqa: F401
        import winrt.windows.foundation  # noqa: F401  (necesario para usar await con WinRT)
        import winrt.windows.storage.streams  # noqa: F401
    except ImportError as exc:
        raise HelloError("Falta el componente de Windows Hello en esta instalación.") from exc
    return KeyCredentialManager, KeyCredentialCreationOption, KeyCredentialStatus, CryptographicBuffer


def _to_ibuffer(data: bytes):
    CryptographicBuffer = _winrt()[3]
    try:
        return CryptographicBuffer.create_from_byte_array(data)
    except TypeError:
        return CryptographicBuffer.create_from_byte_array(list(data))


def _from_ibuffer(buf) -> bytes:
    try:
        return bytes(memoryview(buf))
    except TypeError:
        CryptographicBuffer = _winrt()[3]
        arr = CryptographicBuffer.copy_to_byte_array(buf)
        return bytes(list(arr if not isinstance(arr, tuple) else arr[0]))


def _run_async(coro_factory):
    import asyncio
    return asyncio.run(coro_factory())


def hello_available() -> bool:
    """True si el equipo tiene Windows Hello configurado y los componentes están instalados."""
    try:
        KeyCredentialManager = _winrt()[0]

        async def check():
            return await KeyCredentialManager.is_supported_async()
        return bool(_run_async(check))
    except Exception as exc:                 # noqa: BLE001 - nunca debe tumbar la app
        log.info("Windows Hello no disponible: %s", exc)
        return False


def _credential_name(username: str) -> str:
    return f"CipherVault:{username.lower()}"


def hello_sign(username: str, challenge: bytes, create: bool = False) -> bytes:
    """Muestra el diálogo de Windows Hello y devuelve la firma del reto (bytes)."""
    KeyCredentialManager, Option, Status, _ = _winrt()
    name = _credential_name(username)

    async def flow():
        if create:
            result = await KeyCredentialManager.request_create_async(name, Option.REPLACE_EXISTING)
        else:
            result = await KeyCredentialManager.open_async(name)
        if result.status != Status.SUCCESS:
            return result.status, None
        signed = await result.credential.request_sign_async(_to_ibuffer(challenge))
        if signed.status != Status.SUCCESS:
            return signed.status, None
        return Status.SUCCESS, _from_ibuffer(signed.result)

    status, signature = _run_async(flow)
    if signature is None:
        if status == Status.USER_CANCELED:
            raise HelloError("Cancelaste la verificación de Windows Hello.")
        if status == Status.NOT_FOUND:
            raise HelloError("Windows Hello ya no tiene la clave de CipherVault. Vuelve a activarlo en Configuración.")
        raise HelloError(f"Windows Hello no pudo verificar tu identidad ({status}).")
    return signature


def hello_delete(username: str) -> None:
    try:
        KeyCredentialManager = _winrt()[0]

        async def delete():
            await KeyCredentialManager.delete_async(_credential_name(username))
        _run_async(delete)
    except Exception as exc:                 # noqa: BLE001
        log.info("No se pudo borrar la clave de Windows Hello: %s", exc)


# DPAPI (CryptProtectData) – ata un dato a la cuenta de Windows actual.
def dpapi_protect(data: bytes) -> bytes:
    if os.name != "nt":
        return data
    return _dpapi(data, protect=True)


def dpapi_unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        return data
    return _dpapi(data, protect=False)


def _dpapi(data: bytes, protect: bool) -> bytes:          # pragma: no cover - solo Windows
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    entropy_raw = b"CipherVault/hello/v1"
    ebuf = ctypes.create_string_buffer(entropy_raw, len(entropy_raw))
    entropy = DATA_BLOB(len(entropy_raw), ctypes.cast(ebuf, ctypes.POINTER(ctypes.c_char)))
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), None, ctypes.byref(entropy), None, None, 0x1, ctypes.byref(blob_out))
    if not ok:
        raise HelloError("Windows no pudo proteger/abrir el dato de Windows Hello.")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _kernel32.LocalFree(blob_out.pbData)


def hello_wrap_key(vault_key: bytes, signature: bytes) -> str:
    """Cifra la clave de la bóveda con la clave derivada de la firma de Windows Hello."""
    from cryptography.fernet import Fernet
    wrapping = base64.urlsafe_b64encode(hashlib.sha256(b"CipherVault/hello|" + signature).digest())
    token = Fernet(wrapping).encrypt(vault_key)
    return base64.urlsafe_b64encode(dpapi_protect(token)).decode("ascii")


def hello_unwrap_key(wrapped: str, signature: bytes) -> bytes:
    from cryptography.fernet import Fernet, InvalidToken
    wrapping = base64.urlsafe_b64encode(hashlib.sha256(b"CipherVault/hello|" + signature).digest())
    try:
        token = dpapi_unprotect(base64.urlsafe_b64decode(wrapped.encode("ascii")))
        return Fernet(wrapping).decrypt(token)
    except (InvalidToken, ValueError) as exc:
        raise HelloError("La clave guardada para Windows Hello no coincide. Vuelve a activarlo en Configuración.") from exc
