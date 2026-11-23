# -*- coding: utf-8 -*-
"""Laboratorul 8 - partea A. Scoate si numara esecurile din auth.log.
Generat din programul de laborator, cu codul scris de student."""
import re
from collections import Counter

TIPAR = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port")


def esec(linie):
    """Extrage contul și adresa IP dintr-o autentificare eșuată. Pentru alte rânduri întoarce None."""
    m = TIPAR.search(linie)
    if m is None:
        return None
    return (m.group(1), m.group(2))

def citeste_esecuri(cale):
    """Păstrează, în ordinea din jurnal, încercările pentru care se pot identifica atât contul, cât și adresa. Dacă fișierul lipsește, întoarce o listă goală."""
    esecuri = []
    try:
        with open(cale, encoding="utf-8") as f:
            for linie in f:
                r = esec(linie)
                if r is not None:
                    esecuri.append({"user": r[0], "ip": r[1]})
    except FileNotFoundError:
        print("Fisierul nu exista:", cale)
        return []
    return esecuri

def pe_ip(esecuri):
    """Numără de câte ori apare fiecare adresă IP în lista de încercări eșuate."""
    return Counter(e["ip"] for e in esecuri)

def rezumat(cale):
    """Calculează totalul încercărilor eșuate și distribuția lor pe adrese IP."""
    esecuri = citeste_esecuri(cale)
    return {"esecuri": len(esecuri), "pe_ip": pe_ip(esecuri)}


# ---------------------------------------------------------------------------
#  PARTEA B - detectorul de brute force
# ---------------------------------------------------------------------------

def main():
    import sys
    cale = sys.argv[1] if len(sys.argv) > 1 else 'start/auth.log'
    esecuri = citeste_esecuri(cale)
    counts = pe_ip(esecuri)
    print('Esecuri de autentificare:', len(esecuri))
    for ip, n in counts.most_common():
        print('  %s: %d' % (ip, n))


if __name__ == '__main__':
    main()
