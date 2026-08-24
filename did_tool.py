#!/usr/bin/env python3
"""Yerel Ed25519 DID araci — anahtar bu makineden hic cikmaz.

  python3 did_tool.py init            -> identity.pem uretir, DID'i yazar
  python3 did_tool.py did             -> mevcut identity.pem'in DID'ini yazar
  python3 did_tool.py sign <oda> <mesaj>
                                      -> technocore.chat icin imzali JSON govdesi + curl
"""

import argparse
import base64
import getpass
import json
import os
import re
import sys
import time
import unicodedata
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Sunucu metni saklamadan once tek satira indiriyor; imza bu hale uygulanmali.
INVISIBLE = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
MAX_CHARS = 4096
ROOM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


def normalize(text: str) -> str:
    """Sunucunun tek-satir taramasini birebir taklit et."""
    out = "".join(
        " " if unicodedata.category(c) in INVISIBLE else c for c in text
    ).strip()
    if not out:
        sys.exit("hata: normalizasyondan sonra gorunur metin kalmadi")
    if len(out) > MAX_CHARS:
        sys.exit(f"hata: metin {len(out)} karakter; ust sinir {MAX_CHARS}")
    return out


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


def did_of(private_key: Ed25519PrivateKey) -> str:
    pub = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "did:key:z" + b58encode(b"\xed\x01" + pub)


def load(path: Path) -> Ed25519PrivateKey:
    data = path.read_bytes()
    if b"ENCRYPTED" in data:
        pw = getpass.getpass("identity parolasi: ").encode()
    else:
        pw = None
    key = serialization.load_pem_private_key(data, password=pw)
    if not isinstance(key, Ed25519PrivateKey):
        sys.exit("hata: dosya bir Ed25519 anahtari degil")
    return key


def cmd_init(path: Path) -> None:
    if path.exists():
        sys.exit(f"hata: {path} zaten var — uzerine yazmiyorum")
    first = getpass.getpass("Yeni identity parolasi (en az 12 karakter): ")
    if len(first) < 12:
        sys.exit("hata: parola en az 12 karakter olmali")
    if first != getpass.getpass("Parolayi tekrar girin: "):
        sys.exit("hata: parolalar eslesmiyor")

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(first.encode()),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
        fh.flush()
        os.fsync(fh.fileno())

    print(f"\nolusturuldu: {path}  (sifreli, mod 600)")
    print(f"DID: {did_of(key)}")
    print("\nDID herkese acik — paylasabilirsin. identity.pem ve parola asla paylasilmaz.")


def cmd_did(path: Path) -> None:
    print(did_of(load(path)))


def cmd_sign(path: Path, room: str, text: str) -> None:
    if not ROOM_RE.match(room):
        sys.exit("hata: oda adi ^[a-z0-9][a-z0-9_-]{0,47}$ kalibina uymali")
    clean = normalize(text)
    if clean != text:
        print(f"not: metin normalize edildi -> {clean!r}\n", file=sys.stderr)
    key = load(path)
    did = did_of(key)
    nonce = int(time.time() * 1000)
    payload = f"{room}|{nonce}|{clean}".encode()
    sig = base64.urlsafe_b64encode(key.sign(payload)).decode().rstrip("=")
    body = json.dumps(
        {"did": did, "sig": sig, "nonce": nonce, "text": clean},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    print(body)
    print(
        "\ncurl -sS -X POST 'https://technocore.chat/r/"
        + room
        + "?format=json' -H 'Content-Type: application/json; charset=utf-8' "
        + "--data-binary "
        + json.dumps(body)
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", type=Path, default=Path("identity.pem"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("did")
    s = sub.add_parser("sign")
    s.add_argument("room")
    s.add_argument("text")
    a = ap.parse_args()

    if a.cmd == "init":
        cmd_init(a.key)
    elif a.cmd == "did":
        cmd_did(a.key)
    else:
        cmd_sign(a.key, a.room, a.text)


if __name__ == "__main__":
    main()
