# -*- coding: utf-8 -*-
"""Laboratorul 9 - inventar de procese si jurnal ca obiecte."""
import json
from dataclasses import dataclass, asdict

CAI_SUSPECTE = ('\\Temp\\', '\\Roaming\\')
SUSPECTE_ID = {4625, 1102, 7045}


@dataclass
class Proces:
    """Descrie un proces prin PID, nume, utilizator și calea executabilului."""
    pid: int
    nume: str
    user: str
    cale: str

    def e_suspect(self):
        """Semnalează executabilele a căror cale conține un director Temp sau Roaming."""
        for c in CAI_SUSPECTE:
            if c in self.cale:
                return True
        return False


@dataclass
class Eveniment:
    """Reunește datele unei înregistrări din jurnalul Windows."""
    id: int
    nivel: str
    sursa: str
    cont: str
    mesaj: str

    def e_suspect(self):
        """Semnalează evenimentele cu nivel critic sau cu unul dintre identificatorii urmăriți."""
        return self.id in SUSPECTE_ID or self.nivel == "critical"


def procese_din_json(cale):
    """Citește lista din fișierul JSON și construiește câte un obiect Proces pentru fiecare înregistrare."""
    with open(cale, encoding="utf-8") as f:
        return [Proces(**d) for d in json.load(f)]


def evenimente_din_json(cale):
    """Transformă înregistrările din fișierul JSON în obiecte Eveniment, în ordinea citirii."""
    with open(cale, encoding="utf-8") as f:
        return [Eveniment(**d) for d in json.load(f)]


# ---------------------------------------------------------------------------
#  PARTEA B - clasa Inventar si raportul
# ---------------------------------------------------------------------------

@dataclass
class Inventar:
    """Păstrează lista proceselor din captură pentru filtrare și grupare."""
    procese: list

    @classmethod
    def din_json(cls, cale):
        """Construiește inventarul folosind procesele descrise în fișierul primit."""
        with open(cale, encoding="utf-8") as f:
            return cls([Proces(**d) for d in json.load(f)])

    def __len__(self):
        return len(self.procese)

    def suspecte(self):
        """Selectează procesele marcate de regula de verificare, în ordinea din captură."""
        return [p for p in self.procese if p.e_suspect()]

    def pe_user(self):
        """Grupează numele proceselor după utilizator și păstrează ordinea din inventar pentru fiecare cont."""
        d = {}
        for p in self.procese:
            d.setdefault(p.user, []).append(p.nume)
        return d


def raport(dosar):
    """Combină cele două capturi într-un raport cu totalurile, procesele suspecte și evenimentele semnalate."""
    inv = Inventar.din_json(dosar + "/procese.json")
    ev = evenimente_din_json(dosar + "/evenimente.json")
    return {
        "procese": len(inv),
        "suspecte": [asdict(p) for p in inv.suspecte()],
        "evenimente": len(ev),
        "alarma": [asdict(e) for e in ev if e.e_suspect()],
    }


#

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('capturi')
    p.add_argument('--json', action='store_true')
    a = p.parse_args()
    inv = Inventar.din_json(a.capturi + '/procese.json')
    ev = evenimente_din_json(a.capturi + '/evenimente.json')
    alarma = [e for e in ev if e.e_suspect()]
    if a.json:
        print(json.dumps(raport(a.capturi), indent=2, ensure_ascii=False))
        return
    sus = inv.suspecte()
    print('Procese: %d | suspecte: %d' % (len(inv), len(sus)))
    for p in sus:
        print('  [%d] %s  (%s)  %s' % (p.pid, p.nume, p.user, p.cale))
    print('Evenimente: %d | alarma: %d' % (len(ev), len(alarma)))
    for e in alarma:
        print('  %d [%s] %s: %s' % (e.id, e.nivel, e.cont, e.mesaj))


if __name__ == '__main__':
    main()
