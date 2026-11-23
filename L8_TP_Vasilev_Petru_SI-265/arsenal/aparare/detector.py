# -*- coding: utf-8 -*-
"""Laboratorul 8 - partea B. Detectorul de brute force."""
import argparse, json
from collections import Counter
from arsenal.aparare.parse_auth import citeste_esecuri, pe_ip


def suspecti(counts, prag=10):
    """Selectează adresele care ating pragul și le ordonează descrescător după numărul de încercări. Pragul minim acceptat este 1."""
    if prag < 1:
        raise ValueError("prag invalid: %s (cel putin 1)" % prag)
    rezultat = [(ip, n) for ip, n in counts.items() if n >= prag]
    rezultat.sort(key=lambda p: p[1], reverse=True)
    return rezultat

def raport_json(cale, prag=10):
    """Pregătește pentru export totalul încercărilor eșuate, numărul lor pe adresă și lista adreselor care ating pragul."""
    esecuri = citeste_esecuri(cale)
    counts = pe_ip(esecuri)
    return {"esecuri": len(esecuri),
            "pe_ip": dict(counts),
            "suspecti": suspecti(counts, prag)}

def e_brute_force(counts, ip, prag=10):
    """Verifică dacă numărul de încercări de la adresa dată atinge pragul. Pentru o adresă absentă, numărul de încercări este zero."""
    return counts.get(ip, 0) >= prag

def utilizatori_tintiti(esecuri, ip):
    """Întoarce conturile distincte încercate de la adresa IP aleasă."""
    return {e["user"] for e in esecuri if e["ip"] == ip}


#  

def main():
    p = argparse.ArgumentParser()
    p.add_argument('log')
    p.add_argument('--prag', type=int, default=10)
    p.add_argument('--json', action='store_true')
    a = p.parse_args()
    esecuri = citeste_esecuri(a.log)
    counts = pe_ip(esecuri)
    sus = suspecti(counts, a.prag)
    if a.json:
        print(json.dumps({'esecuri': len(esecuri),
                          'pe_ip': dict(counts),
                          'suspecti': sus}, indent=2))
        return
    print('Esecuri de autentificare:', len(esecuri))
    for ip, n in counts.most_common():
        print('  %s: %d' % (ip, n))
    print('Suspecti (prag %d):' % a.prag)
    for ip, n in sus:
        print('  %s  (%d incercari)  BRUTE FORCE' % (ip, n))


if __name__ == '__main__':
    main()
