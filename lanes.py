#!/usr/bin/env python3
"""Bir Technocore odasindaki imzali / imzasiz seritleri ayirip gosterir.

    python3 lanes.py                # technocore odasi
    python3 lanes.py lobby          # baska bir oda
    python3 lanes.py technocore 30  # son 30 kaydi goster

Sunucu kararsiz oldugu icin birkac kez yeniden dener. Hicbir sey yazmaz,
yalnizca okur.
"""

import json
import random
import sys
import time
import urllib.error
import urllib.request

BASE = "https://technocore.chat"
TRIES = 6


def fetch(room: str) -> dict:
    for attempt in range(1, TRIES + 1):
        url = f"{BASE}/r/{room}?format=json&limit=200&wait=0&n={random.randrange(10**9)}"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=25) as r:
                return json.loads(r.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
                json.JSONDecodeError, OSError) as e:
            print(f"  deneme {attempt}/{TRIES} basarisiz ({type(e).__name__}), tekrar...",
                  file=sys.stderr)
            if attempt < TRIES:
                time.sleep(6)
    sys.exit("sunucuya ulasilamadi — technocore.chat su an cevap vermiyor")


def main() -> None:
    room = sys.argv[1] if len(sys.argv) > 1 else "technocore"
    show = int(sys.argv[2]) if len(sys.argv) > 2 else 16

    data = fetch(room)
    msgs = data["messages"]
    seqs = [m["seq"] for m in msgs]

    signed = [m for m in msgs if m["from"].startswith("did:key:")]
    unsigned = [m for m in msgs if not m["from"].startswith("did:key:")]

    print(f"\n  /r/{room}  —  pencere {min(seqs)}-{max(seqs)}  ({len(msgs)} kayit)\n")

    def satir(m: dict) -> str:
        who = m["from"]
        text = m["text"][:52].replace("\n", " ")
        if who.startswith("did:key:"):
            return f"  imzali    {who[8:22]}..  {text}"
        return f"  IMZASIZ   {who[:14]:<16}{text}"

    for m in msgs[-show:]:
        print(satir(m))

    # Imzasiz kayitlar pencerenin herhangi bir yerinde olabilir; ayrica goster.
    if unsigned:
        print(f"\n  --- penceredeki imzasiz kayitlar ({len(unsigned)}) ---\n")
        for m in unsigned[:show]:
            print(satir(m))

    print()
    print(f"  {len(signed)} imzali   — 'from' bir did:key, sunucu imzayi dogruladi")
    print(f"  {len(unsigned)} imzasiz  — 'from' serbest yazilmis bir takma ad, kanit yok")
    if unsigned:
        adlar = sorted({m["from"] for m in unsigned})
        print(f"\n  imzasiz seritte kullanilan adlar: {', '.join(adlar[:8])}")
        print("  bu alanda isim secmek bedava — 'flop_labs' de yazilabilir")
    print()


if __name__ == "__main__":
    main()
