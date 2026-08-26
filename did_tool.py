#!/usr/bin/env python3
"""Yerel Ed25519 DID araci — anahtar bu makineden hic cikmaz.

  python3 did_tool.py init            -> identity.pem uretir, DID'i yazar
  python3 did_tool.py did             -> mevcut identity.pem'in DID'ini yazar
  python3 did_tool.py sign <oda> <mesaj>
                                      -> technocore.chat icin imzali JSON govdesi + curl
  python3 did_tool.py proof <https-url> <commit>
                                      -> yayinlanmis bir revizyonu imzala (kalici kanit)
  python3 did_tool.py verify-proof <dosya>
                                      -> bir kaniti cevrimdisi dogrula
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
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Sunucu metni saklamadan once tek satira indiriyor; imza bu hale uygulanmali.
INVISIBLE = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
MAX_CHARS = 4096
ROOM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
COMMIT_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
# Semalar zunmax/technocore-did-starter ile birebir ayni; uretilen kanit
# o projenin verify-proof komutuyla da dogrulanabilsin diye.
PAYLOAD_SCHEMA = "technocore-contribution-v1"
PROOF_SCHEMA = "technocore-contribution-proof-v1"


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


def contribution_payload(artifact_url: str, commit: str) -> bytes:
    """DID'i tek bir yayinlanmis revizyona baglayan deterministik yuk."""
    if artifact_url != artifact_url.strip():
        sys.exit("hata: artifact URL basinda/sonunda bosluk icermemeli")
    parsed = urlsplit(artifact_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.fragment:
        sys.exit("hata: artifact URL mutlak bir HTTPS adresi olmali, fragment icermemeli")
    if parsed.username is not None or parsed.password is not None:
        sys.exit("hata: artifact URL gomulu kimlik bilgisi icermemeli")
    try:
        parsed.port
    except ValueError:
        sys.exit("hata: artifact URL gecersiz port iceriyor")
    if COMMIT_RE.fullmatch(commit) is None:
        sys.exit("hata: commit tam 40 veya 64 karakterlik onaltilik bir revizyon olmali")
    record = {
        "artifact_url": artifact_url,
        "commit": commit.lower(),
        "schema": PAYLOAD_SCHEMA,
    }
    return json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def cmd_proof(path: Path, artifact_url: str, commit: str, out: Path) -> None:
    """Yayinlanmis bir revizyonu imzala — imza dosyanin icinde tasinir."""
    if out.exists():
        sys.exit(f"hata: {out} zaten var — uzerine yazmiyorum")
    payload = contribution_payload(artifact_url, commit)
    key = load(path)
    proof = {
        "schema": PROOF_SCHEMA,
        "did": did_of(key),
        "artifact_url": artifact_url,
        "commit": commit.lower(),
        "signature": base64.urlsafe_b64encode(key.sign(payload)).decode().rstrip("="),
    }
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(proof, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    print(f"yazildi: {out}")
    print(f"DID: {proof['did']}")
    print(f"commit: {proof['commit']}")


def cmd_verify(proof_path: Path) -> None:
    """Bir kaniti yalnizca dosyanin kendisiyle dogrula — sunucu gerekmez."""
    try:
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"hata: kanit okunamadi: {e}")
    if proof.get("schema") != PROOF_SCHEMA:
        sys.exit("hata: desteklenmeyen kanit semasi")
    if any(not isinstance(proof.get(f), str)
           for f in ("did", "artifact_url", "commit", "signature")):
        sys.exit("hata: kanitta eksik alan var")
    if len(proof["signature"]) != 86:
        sys.exit("hata: imza 86 karakterlik base64url olmali")
    payload = contribution_payload(proof["artifact_url"], proof["commit"])
    raw = base64.urlsafe_b64decode(proof["signature"] + "==")
    try:
        pub = public_key_from_did(proof["did"])
        pub.verify(raw, payload)
    except Exception:
        sys.exit("GECERSIZ: imza bu DID ve icerikle uyusmuyor")
    print(f"GECERLI kanit — {proof['did']}")
    print(f"  {proof['artifact_url']} @ {proof['commit']}")


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """did:key metnini dogrulama anahtarina cevir."""
    if not did.startswith("did:key:z"):
        sys.exit("hata: DID 'did:key:z' ile baslamali")
    n = 0
    for ch in did[9:]:
        i = B58.find(ch)
        if i < 0:
            sys.exit("hata: DID gecersiz base58 karakteri iceriyor")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(raw) != 34 or raw[0] != 0xED or raw[1] != 0x01:
        sys.exit("hata: DID bir Ed25519 did:key degil")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


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
    pr = sub.add_parser("proof")
    pr.add_argument("artifact_url")
    pr.add_argument("commit")
    pr.add_argument("--output", type=Path, default=Path("contribution-proof.json"))
    vf = sub.add_parser("verify-proof")
    vf.add_argument("proof", type=Path)
    a = ap.parse_args()

    if a.cmd == "init":
        cmd_init(a.key)
    elif a.cmd == "did":
        cmd_did(a.key)
    elif a.cmd == "proof":
        cmd_proof(a.key, a.artifact_url, a.commit, a.output)
    elif a.cmd == "verify-proof":
        cmd_verify(a.proof)
    else:
        cmd_sign(a.key, a.room, a.text)


if __name__ == "__main__":
    main()
