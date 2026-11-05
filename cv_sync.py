"""
cv_sync.py – Sincronización por carpeta y bóveda de equipo de CipherVault.

Ninguna de las dos funciones usa servidores de S.C.A: los datos viajan en archivos
CIFRADOS dentro de una carpeta que el usuario ya sincroniza (OneDrive, Google Drive,
Dropbox o una carpeta compartida de la red de la empresa).

  · Sincronización personal (.cvsync): la misma cuenta en varios equipos. El archivo se
    cifra con una clave derivada de la contraseña maestra (PBKDF2) y una sal propia.
  · Bóveda de equipo (.cvteam): una clave de equipo aleatoria cifra las entradas; esa
    clave se "sella" para cada miembro con su clave pública X25519. El administrador
    agrega a alguien pegando su código de miembro; al quitar a alguien se genera una
    clave de equipo nueva.

Cada entrada tiene un identificador estable (uid) y una fecha de actualización (UTC,
"YYYY-MM-DD HH:MM:SS"). Al mezclar gana la versión más reciente, y una lápida
(tombstone) borra la entrada si es posterior a su última modificación.

© 2026 S.C.A - CipherVault. Todos los derechos reservados. Software con licencia
comercial: queda prohibida su copia, distribución o modificación sin autorización
expresa del autor.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SYNC_FORMAT = "CipherVault sync v1"
TEAM_FORMAT = "CipherVault team v1"
TOMBSTONE_DAYS = 400                     # las lápidas más viejas se descartan
ENTRY_FIELDS = ("uid", "service", "username", "password", "notes", "url", "totp", "category",
                "created_at", "updated_at")
ROLES = {"admin": "Administrador", "editor": "Editor", "lector": "Solo lectura"}
ACTIVITY_MAX = 1000                      # eventos que guarda el registro de actividad del equipo
STALE_DAYS = 180                         # informe de seguridad: contraseñas sin cambiar en ~6 meses


class SyncError(Exception):
    """Error con un mensaje listo para mostrar al usuario."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def utc_now() -> str:
    """Misma forma que CURRENT_TIMESTAMP de SQLite (UTC)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def new_uid() -> str:
    return uuid.uuid4().hex


# ══════════════════════════════════════════════
#  MEZCLA (común a sincronización y equipo)
# ══════════════════════════════════════════════
def clean_entry(entry: dict) -> dict:
    out = {k: str(entry.get(k) or "") for k in ENTRY_FIELDS}
    out["category"] = out["category"] or "General"
    return out


def merge(local_entries: list[dict], local_tombs: dict, remote_entries: list[dict],
          remote_tombs: dict) -> tuple[list[dict], dict]:
    """Une dos copias. Devuelve (entradas, lápidas) resultantes."""
    tombs: dict[str, str] = {}
    for source in (local_tombs or {}, remote_tombs or {}):
        for uid, when in source.items():
            if when and (uid not in tombs or when > tombs[uid]):
                tombs[uid] = when
    best: dict[str, dict] = {}
    for entry in list(local_entries or []) + list(remote_entries or []):
        entry = clean_entry(entry)
        uid = entry["uid"]
        if not uid:
            continue
        current = best.get(uid)
        if current is None or entry["updated_at"] > current["updated_at"] or (
                entry["updated_at"] == current["updated_at"]
                and json.dumps(entry, sort_keys=True) > json.dumps(current, sort_keys=True)):
            best[uid] = entry
    entries = [e for uid, e in best.items() if not (uid in tombs and tombs[uid] >= e["updated_at"])]
    limit = (datetime.now(timezone.utc) - timedelta(days=TOMBSTONE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    tombs = {uid: when for uid, when in tombs.items() if when >= limit}
    entries.sort(key=lambda e: (e["service"].lower(), e["uid"]))
    return entries, tombs


def plan_local_changes(local_entries: list[dict], merged: list[dict]) -> tuple[list[dict], list[str]]:
    """Qué hay que escribir en la base local para que quede igual a `merged`:
    (entradas a insertar/actualizar, uids a borrar)."""
    local = {e["uid"]: clean_entry(e) for e in local_entries if e.get("uid")}
    target = {e["uid"]: e for e in merged}
    upserts = [e for uid, e in target.items() if uid not in local or local[uid] != e]
    deletes = [uid for uid in local if uid not in target]
    return upserts, deletes


# ══════════════════════════════════════════════
#  ARCHIVOS: escritura atómica y copias en conflicto
# ══════════════════════════════════════════════
def atomic_write(path: Path, data: dict):
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def conflict_copies(path: Path) -> list[Path]:
    """Copias que crean OneDrive/Drive/Dropbox cuando dos equipos guardan a la vez
    ("archivo-PC.cvsync", "archivo (1).cvsync", "archivo (copia en conflicto…).cvsync")."""
    path = Path(path)
    if not path.parent.is_dir():
        return []
    stem = re.escape(path.stem)
    pattern = re.compile(rf"^{stem}[ \-_(].*{re.escape(path.suffix)}$", re.IGNORECASE)
    return [p for p in path.parent.iterdir() if p != path and p.is_file() and pattern.match(p.name)]


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        raise SyncError(f"No se pudo leer {Path(path).name}: el archivo está dañado o incompleto.") from exc
    if not isinstance(data, dict):
        raise SyncError(f"{Path(path).name} no es un archivo de CipherVault.")
    return data


# ══════════════════════════════════════════════
#  SINCRONIZACIÓN PERSONAL (.cvsync)
# ══════════════════════════════════════════════
def sync_file_name(username: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", username)
    return f"CipherVault_sync_{safe}.cvsync"


def derive_sync_key(master_password: str, salt: bytes, iterations: int) -> bytes:
    raw = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(raw)


def sync_file_info(path: Path) -> dict | None:
    """Cabecera del archivo (sal e iteraciones) o None si no existe."""
    try:
        data = _read_json(path)
    except FileNotFoundError:
        return None
    if data.get("format") != SYNC_FORMAT:
        raise SyncError("Ese archivo no es una sincronización de CipherVault.")
    return {"salt": _unb64(data["salt"]), "iterations": int(data["iterations"])}


def new_sync_header(iterations: int) -> dict:
    return {"salt": os.urandom(16), "iterations": iterations}


def read_sync(path: Path, key: bytes) -> tuple[list[dict], dict]:
    data = _read_json(path)
    if data.get("format") != SYNC_FORMAT:
        raise SyncError("Ese archivo no es una sincronización de CipherVault.")
    try:
        payload = json.loads(Fernet(key).decrypt(data["ciphertext"].encode("ascii")))
    except (InvalidToken, KeyError, ValueError) as exc:
        raise SyncError("La contraseña maestra no abre el archivo de sincronización (¿la cambiaste en "
                        "otro equipo?).") from exc
    return list(payload.get("entries") or []), dict(payload.get("tombstones") or {})


def write_sync(path: Path, key: bytes, header: dict, entries: list[dict], tombs: dict, device: str):
    payload = json.dumps({"entries": entries, "tombstones": tombs}, ensure_ascii=False).encode("utf-8")
    atomic_write(path, {
        "format": SYNC_FORMAT, "salt": _b64(header["salt"]), "iterations": header["iterations"],
        "updated": utc_now(), "device": device[:60],
        "ciphertext": Fernet(key).encrypt(payload).decode("ascii"),
    })


def sync_folder(path: Path, key: bytes, header: dict, local_entries: list[dict], local_tombs: dict,
                device: str) -> tuple[list[dict], dict]:
    """Lee el archivo (y sus copias en conflicto), mezcla con lo local, guarda el resultado
    y devuelve (entradas, lápidas) mezcladas para aplicarlas en la base local."""
    path = Path(path)
    entries, tombs = list(local_entries), dict(local_tombs)
    for candidate in [path] + conflict_copies(path):
        try:
            remote_e, remote_t = read_sync(candidate, key)
        except FileNotFoundError:
            continue
        except SyncError:
            if candidate == path:
                raise
            continue                     # copia en conflicto de otra clave: se ignora
        entries, tombs = merge(entries, tombs, remote_e, remote_t)
    entries, tombs = merge(entries, tombs, [], {})
    write_sync(path, key, header, entries, tombs, device)
    for copy in conflict_copies(path):
        try:
            read_sync(copy, key)
            copy.unlink()                # ya quedó mezclada en el archivo principal
        except (SyncError, OSError):
            pass
    return entries, tombs


# ══════════════════════════════════════════════
#  BÓVEDA DE EQUIPO (.cvteam)
# ══════════════════════════════════════════════
MEMBER_CODE_PREFIX = "CVM1-"


def new_member_keypair() -> tuple[bytes, bytes]:
    """(privada, pública) X25519 en bytes crudos de 32."""
    private = X25519PrivateKey.generate()
    priv = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub


def member_code(public_key: bytes) -> str:
    """Código que el empleado le envía al administrador (incluye un control de 2 bytes
    para detectar errores al copiarlo)."""
    check = hashlib.sha256(public_key).digest()[:2]
    return MEMBER_CODE_PREFIX + base64.b32encode(public_key + check).decode("ascii").rstrip("=")


def parse_member_code(code: str) -> bytes:
    text = re.sub(r"\s", "", code or "").upper()
    if not text.startswith(MEMBER_CODE_PREFIX):
        raise SyncError("El código de miembro debe empezar por CVM1-. Pídele a la persona que lo copie completo.")
    body = text[len(MEMBER_CODE_PREFIX):]
    try:
        raw = base64.b32decode(body + "=" * (-len(body) % 8))
    except ValueError as exc:
        raise SyncError("El código de miembro no es válido.") from exc
    if len(raw) != 34 or hashlib.sha256(raw[:32]).digest()[:2] != raw[32:]:
        raise SyncError("El código de miembro está incompleto o tiene un error al copiarlo.")
    return raw[:32]


def fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(b"CipherVault/member|" + public_key).hexdigest()[:24]


def _seal_key(eph_pub: bytes, member_pub: bytes, shared: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"CipherVault/team-seal/v1|" + eph_pub + member_pub)
    return base64.urlsafe_b64encode(hkdf.derive(shared))


def seal(team_key: bytes, member_pub: bytes) -> str:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(member_pub))
    token = Fernet(_seal_key(eph_pub, member_pub, shared)).encrypt(team_key)
    return _b64(eph_pub + token)


def unseal(sealed: str, member_priv: bytes) -> bytes:
    raw = _unb64(sealed)
    eph_pub, token = raw[:32], raw[32:]
    private = X25519PrivateKey.from_private_bytes(member_priv)
    member_pub = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = private.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    try:
        return Fernet(_seal_key(eph_pub, member_pub, shared)).decrypt(token)
    except InvalidToken as exc:
        raise SyncError("No se pudo abrir la clave del equipo.") from exc


def merge_activity(a: list[dict], b: list[dict]) -> list[dict]:
    """Une dos registros de actividad (sin repetir eventos), en orden y con tope ACTIVITY_MAX."""
    seen = {}
    for event in list(a or []) + list(b or []):
        if isinstance(event, dict) and event.get("id"):
            seen.setdefault(event["id"], event)
    return sorted(seen.values(), key=lambda e: (e.get("at", ""), e["id"]))[-ACTIVITY_MAX:]


def security_report(entries: list[dict], strength_of, now: datetime | None = None) -> dict:
    """Informe de seguridad de la bóveda del equipo.
    strength_of(password) -> "Débil" | "Media" | "Fuerte" | ... (la misma escala de la app).
    Devuelve listas de servicios: débiles, repetidas (misma contraseña en varias entradas),
    sin cambiar en STALE_DAYS días y sin 2FA, más un puntaje de 0 a 100."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    weak, stale, no_2fa, by_password = [], [], [], {}
    for e in entries:
        name = e.get("service", "") or "—"
        pwd = e.get("password", "")
        if str(strength_of(pwd)).lower().startswith(("débil", "debil", "muy débil", "muy debil")):
            weak.append(name)
        by_password.setdefault(pwd, []).append(name)
        try:
            changed = datetime.strptime((e.get("updated_at") or "")[:19], "%Y-%m-%d %H:%M:%S")
            if now - changed > timedelta(days=STALE_DAYS):
                stale.append(name)
        except ValueError:
            pass
        if not e.get("totp"):
            no_2fa.append(name)
    reused = sorted(n for names in by_password.values() if len(names) > 1 for n in names)
    total = len(entries)
    problems = len(set(weak) | set(reused) | set(stale))
    score = 100 if not total else round(100 * (total - problems) / total)
    return {"total": total, "weak": sorted(weak), "reused": reused, "stale": sorted(stale),
            "no_2fa": sorted(no_2fa), "score": score}


class TeamVault:
    """Archivo .cvteam abierto con la clave privada de un miembro."""

    def __init__(self, path: Path, team_id: str, team_key: bytes, key_version: int, payload: dict,
                 my_fp: str):
        self.path = Path(path)
        self.team_id = team_id
        self.team_key = team_key
        self.key_version = key_version
        self.payload = payload
        self.my_fp = my_fp

    # ── propiedades ──
    @property
    def name(self) -> str:
        return self.payload.get("name", "Equipo")

    @property
    def members(self) -> dict:
        return self.payload.setdefault("members", {})

    @property
    def entries(self) -> list[dict]:
        return self.payload.setdefault("entries", [])

    @property
    def tombstones(self) -> dict:
        return self.payload.setdefault("tombstones", {})

    @property
    def activity(self) -> list[dict]:
        """Registro de actividad: quién creó, editó, borró o copió cada entrada y los cambios de
        miembros. Va cifrado dentro del archivo, como todo lo demás."""
        return self.payload.setdefault("activity", [])

    @property
    def my_name(self) -> str:
        return self.members.get(self.my_fp, {}).get("name", "Miembro")

    def _log(self, action: str, target: str = ""):
        self.activity.append({"id": new_uid(), "at": utc_now(), "by": self.my_fp, "by_name": self.my_name,
                              "action": action, "target": target})

    def log_copy(self, entry: dict, what: str = "la contraseña"):
        """Anota que este miembro copió un dato de una entrada (se guarda con save_merged)."""
        self._log(f"copió {what} de", entry.get("service", ""))

    @property
    def my_role(self) -> str:
        return self.members.get(self.my_fp, {}).get("role", "lector")

    @property
    def can_edit(self) -> bool:
        return self.my_role in ("admin", "editor")

    @property
    def is_admin(self) -> bool:
        return self.my_role == "admin"

    # ── crear / abrir / guardar ──
    @classmethod
    def create(cls, folder: Path, name: str, admin_pub: bytes, admin_name: str, admin_email: str) -> "TeamVault":
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name.strip())[:40] or "equipo"
        path = Path(folder) / f"CipherVault_equipo_{safe}.cvteam"
        if path.exists():
            raise SyncError(f"Ya existe un equipo con ese nombre en esa carpeta:\n{path.name}")
        fp = fingerprint(admin_pub)
        payload = {"name": name.strip(), "members": {fp: {
            "name": admin_name, "email": admin_email, "role": "admin",
            "pubkey": _b64(admin_pub), "added_at": utc_now()}}, "entries": [], "tombstones": {}}
        vault = cls(path, new_uid(), Fernet.generate_key(), 1, payload, fp)
        vault._save_raw()
        return vault

    @classmethod
    def open(cls, path: Path, my_priv: bytes) -> "TeamVault":
        data = _read_json(path)
        if data.get("format") != TEAM_FORMAT:
            raise SyncError("Ese archivo no es una bóveda de equipo de CipherVault.")
        my_pub = X25519PrivateKey.from_private_bytes(my_priv).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        fp = fingerprint(my_pub)
        sealed = (data.get("keys") or {}).get(fp)
        if not sealed:
            raise SyncError("No eres miembro de este equipo (o el administrador te quitó). "
                            "Envíale tu código de miembro para que te agregue.")
        team_key = unseal(sealed, my_priv)
        try:
            payload = json.loads(Fernet(team_key).decrypt(data["ciphertext"].encode("ascii")))
        except (InvalidToken, KeyError, ValueError) as exc:
            raise SyncError("La bóveda del equipo está dañada.") from exc
        vault = cls(path, data.get("team_id", ""), team_key, int(data.get("key_version", 1)), payload, fp)
        vault._merge_conflict_copies()
        return vault

    def _save_raw(self):
        keys = {fp: seal(self.team_key, _unb64(m["pubkey"])) for fp, m in self.members.items()}
        token = Fernet(self.team_key).encrypt(json.dumps(self.payload, ensure_ascii=False).encode("utf-8"))
        atomic_write(self.path, {"format": TEAM_FORMAT, "team_id": self.team_id,
                                 "key_version": self.key_version, "updated": utc_now(),
                                 "keys": keys, "ciphertext": token.decode("ascii")})

    def _merge_conflict_copies(self):
        merged_any = False
        for copy in conflict_copies(self.path):
            try:
                data = _read_json(copy)
                payload = json.loads(Fernet(self.team_key).decrypt(data["ciphertext"].encode("ascii")))
            except (SyncError, InvalidToken, KeyError, ValueError, OSError):
                continue
            entries, tombs = merge(self.entries, self.tombstones, payload.get("entries", []),
                                   payload.get("tombstones", {}))
            self.payload["entries"], self.payload["tombstones"] = entries, tombs
            self.payload["activity"] = merge_activity(self.activity, payload.get("activity", []))
            merged_any = True
            try:
                copy.unlink()
            except OSError:
                pass
        if merged_any:
            self._save_raw()

    def refresh(self, my_priv: bytes) -> "TeamVault":
        return TeamVault.open(self.path, my_priv)

    def save_merged(self, my_priv: bytes):
        """Guarda los cambios mezclándolos con lo que otros hayan guardado mientras tanto."""
        try:
            disk = TeamVault.open(self.path, my_priv)
        except FileNotFoundError:
            disk = None
        if disk is not None:
            if disk.key_version > self.key_version:
                # el administrador rotó la clave: se adopta la nueva
                self.team_key, self.key_version = disk.team_key, disk.key_version
            members = dict(disk.members)
            if self.is_admin:
                members = dict(self.members)
            self.payload["members"] = members
            entries, tombs = merge(self.entries, self.tombstones, disk.entries, disk.tombstones)
            self.payload["entries"], self.payload["tombstones"] = entries, tombs
            self.payload["activity"] = merge_activity(self.activity, disk.activity)
        if self.my_fp not in self.members:
            raise SyncError("Ya no eres miembro de este equipo.")
        self._save_raw()

    # ── entradas ──
    def upsert(self, entry: dict):
        if not self.can_edit:
            raise SyncError("Tu rol en el equipo es de solo lectura.")
        entry = clean_entry(entry)
        entry["uid"] = entry["uid"] or new_uid()
        entry["created_at"] = entry["created_at"] or utc_now()
        entry["updated_at"] = utc_now()
        is_new = not any(e.get("uid") == entry["uid"] for e in self.entries)
        self.payload["entries"] = [e for e in self.entries if e.get("uid") != entry["uid"]] + [entry]
        self._log("creó" if is_new else "editó", entry["service"])
        return entry

    def delete(self, uid: str):
        if not self.can_edit:
            raise SyncError("Tu rol en el equipo es de solo lectura.")
        gone = next((e for e in self.entries if e.get("uid") == uid), {})
        self.payload["entries"] = [e for e in self.entries if e.get("uid") != uid]
        self.tombstones[uid] = utc_now()
        self._log("eliminó", gone.get("service", ""))

    # ── miembros (solo administrador) ──
    def add_member(self, code: str, name: str, email: str, role: str) -> str:
        if not self.is_admin:
            raise SyncError("Solo un administrador puede agregar miembros.")
        if role not in ROLES:
            raise SyncError("Rol no válido.")
        pub = parse_member_code(code)
        fp = fingerprint(pub)
        if fp in self.members:
            raise SyncError("Esa persona ya es miembro del equipo.")
        self.members[fp] = {"name": name.strip() or "Miembro", "email": email.strip().lower(),
                            "role": role, "pubkey": _b64(pub), "added_at": utc_now()}
        self._log("agregó a", f"{self.members[fp]['name']} ({ROLES[role]})")
        return fp

    def set_role(self, fp: str, role: str):
        if not self.is_admin:
            raise SyncError("Solo un administrador puede cambiar roles.")
        if role not in ROLES or fp not in self.members:
            raise SyncError("Miembro o rol no válido.")
        if fp == self.my_fp and role != "admin" and sum(m["role"] == "admin" for m in self.members.values()) == 1:
            raise SyncError("El equipo necesita al menos un administrador.")
        self.members[fp]["role"] = role
        self._log("cambió el rol de", f"{self.members[fp]['name']} a {ROLES[role]}")

    def remove_member(self, fp: str):
        """Quita a alguien y ROTA la clave del equipo: el archivo nuevo ya no se abre con la
        clave anterior. (Lo que esa persona ya vio no se puede "des-ver": conviene cambiar
        las contraseñas importantes.)"""
        if not self.is_admin:
            raise SyncError("Solo un administrador puede quitar miembros.")
        if fp == self.my_fp:
            raise SyncError("No puedes quitarte a ti mismo. Nombra otro administrador primero.")
        if fp not in self.members:
            raise SyncError("Ese miembro no existe.")
        self._log("quitó a", self.members[fp].get("name", ""))
        del self.members[fp]
        self.team_key = Fernet.generate_key()
        self.key_version += 1
