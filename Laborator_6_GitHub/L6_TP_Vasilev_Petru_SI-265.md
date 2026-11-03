# Raport la Lucrarea de laborator Nr. 6

**Universitatea Tehnică a Moldovei**
Facultatea Calculatoare, Informatică și Microelectronică
Disciplina: Tehnici de programare

**Tema:** GitHub, pas cu pas

| | |
|---|---|
| A efectuat | st. gr. SI-265 Vasilev Petru |
| A verificat | asistent universitar Cristian Gonceari |
| Username GitHub | `Pharizhanin` |
| Profil | https://github.com/Pharizhanin |

Chișinău – 2026

---

## 1. Scopul lucrării

Scopul a fost să învăț fluxul de bază git + GitHub: să configurez git pe calculator, să creez depozite, să salvez schimbări prin commit, să le trimit cu `push`, să aduc înapoi cu `pull` și să citesc istoria unui proiect. Am obținut două depozite publice de exercițiu, create în două moduri diferite: unul pornit de pe GitHub, iar celălalt pornit de pe calculator.

## 2. Depozitele realizate

| Depozit | Link | Ce conține |
|---|---|---|
| exercitiu-git | https://github.com/Pharizhanin/exercitiu-git | `README.md`, `salut.py`, `.gitignore`, 4 commit-uri, Public |
| exercitiu-2 | https://github.com/Pharizhanin/exercitiu-2 | `README.md`, creat cu `git init` și trimis cu `push -u`, Public |

## 3. Ce am exersat la fiecare pas

| Pas | Ce am exersat |
|---|---|
| A1. Contul GitHub | M-am autentificat în contul meu GitHub (`Pharizhanin`) și am verificat că adresa de e-mail din cont e cea pe care o folosesc și în git. |
| A2. Configurarea git | Am verificat versiunea cu `git --version` și am setat o singură dată `user.name`, `user.email`, `init.defaultBranch main` și `pull.rebase false`, apoi am controlat totul cu `git config --global --list`. |
| A3. Primul depozit pe GitHub | Am creat din browser depozitul public `exercitiu-git` cu un `README.md`, iar GitHub a făcut automat primul commit, „Initial commit”. |
| A4. git clone | Am copiat adresa HTTPS de la butonul Code și am clonat depozitul cu `git clone`, după care am lucrat doar din folderul `exercitiu-git`. |
| A5. status, add, commit | Am creat `salut.py` și am urmărit cu `git status` cum fișierul trece din „Untracked” în „Changes to be committed” după `git add`, apoi l-am salvat în istorie cu `git commit -m "Adaug salut.py"`. |
| A6. git push | Am trimis commit-ul pe GitHub cu `git push`, după ce m-am autentificat prin browser, și am văzut `salut.py` apărând pe pagina depozitului. |
| A7. git pull | Am editat `README.md` direct pe GitHub, adăugând rândul „Aici exersez git.”, și am adus schimbarea pe calculator cu `git pull`, care a făcut un fast-forward. |
| A8. .gitignore | Am creat mediul virtual `.venv` și am scris un `.gitignore` cu `.venv/` și `__pycache__/`, ca git să nu urce miile de fișiere ale mediului, apoi am trimis regula cu commit și push. |
| A9. log și diff | Am citit istoria cu `git log --oneline` (4 commit-uri) și am văzut cu `git diff` rândul adăugat cu `+` în `salut.py`, apoi am anulat schimbarea cu `git restore`. |
| A10. Al doilea depozit, de pe calculator | Am pornit invers: `git init` în folderul `exercitiu-2` și primul commit local, apoi am legat depozitul gol de pe GitHub cu `git remote add origin` și l-am trimis cu `git push -u origin main`. |

## 4. Istoria depozitului exercitiu-git

```
git log --oneline
<cod> Ignor mediul virtual
<cod> Update README.md
<cod> Adaug salut.py
<cod> Initial commit
```

Codurile commit-urilor sunt cele din pagina „commits” a depozitului.

## 5. Observații

- `git status` mi-a arătat la fiecare pas în ce stare e fișierul. Fără el nu aș fi știut că un fișier nou nu intră în commit până nu îi dau `git add`.
- La A8, cu Python 3.13 sau mai nou, `.venv` poate să nu apară deloc în `git status --short`, pentru că Python pune singur un `.gitignore` în interiorul lui. Am făcut oricum `.gitignore`-ul propriu, pentru că protejează și `__pycache__/`.
- Pe Windows, avertismentul „LF will be replaced by CRLF” nu e o eroare. E vorba doar de sfârșitul de rând.
- Regula pe care o păstrez: `git pull` înainte de lucru și `git push` după.

## 6. Concluzii

Am înțeles diferența dintre git, care ține istoria pe calculatorul meu, și GitHub, care ține o copie a ei pe internet. Am lucrat cu ambele direcții de sincronizare: `push` trimite fotografiile mele pe GitHub, iar `pull` aduce ce s-a schimbat acolo. Am văzut și cele două moduri de a porni un proiect: clonând un depozit creat pe GitHub sau făcând `git init` local și legându-l apoi de un depozit gol prin `remote add` și `push -u`. Istoria cu commit-uri mici și mesaje clare face proiectul ușor de urmărit și de explicat.

## 7. Bibliografie

1. Fișa „Laboratorul 6. GitHub, pas cu pas”, disciplina Tehnici de programare, UTM, FCIM, 2026.
2. Pro Git (S. Chacon, B. Straub), https://git-scm.com/book/ro/v2
3. GitHub Docs: Getting started with Git, https://docs.github.com/en/get-started/getting-started-with-git
4. Documentația git, https://git-scm.com/docs
