ALPHABET = "AĂÂBCDEFGHIÎJKLMNOPQRSȘTȚUVWXYZ"
LOWER = "aăâbcdefghiîjklmnopqrsștțuvwxyz"
N = 31

# Variante vechi (sedila) pe care tastatura le poate da in loc de virgula.
SEDILA_TO_VIRGULA = {
    "Ş": "Ș",
    "ş": "ș",
    "Ţ": "Ț",
    "ţ": "ț",
}


def normalize_char(ch):
    #Inlocuieste Ş/Ţ cu sedila prin Ș/Ț cu virgula.
    if ch in SEDILA_TO_VIRGULA:
        return SEDILA_TO_VIRGULA[ch]
    return ch


def letter_to_index(letter, alphabet):
#Returneaza pozitia literei in alfabetul dat (0..n-1). Fara ASCI
    i = 0
    while i < len(alphabet):
        if alphabet[i] == letter:
            return i
        i += 1
    return -1


def index_to_letter(index, alphabet):
    #Returneaza litera de pe pozitia index din alfabetul dat.
    return alphabet[index]


def is_latin_letter(ch):
    #Verifica daca e litera din alfabetul roman (majuscula sau minuscula).
    ch = normalize_char(ch)
    if letter_to_index(ch, ALPHABET) != -1:
        return True
    if letter_to_index(ch, LOWER) != -1:
        return True
    return False


def to_upper_letter(ch):
    #ransforma o litera romana in majuscula, dupa tabelele proprii
    ch = normalize_char(ch)
    pos = letter_to_index(ch, ALPHABET)
    if pos != -1:
        return ch
    pos = letter_to_index(ch, LOWER)
    return ALPHABET[pos]


def prepare_message(text):
#Verifica textul: doar litere romane si spatii.
  #Returneaza (ok, mesaj_curat sau text_de_eroare).
    for ch in text:          
        if ch == " ":
            continue
        if not is_latin_letter(ch):
            return False, "Caractere permise: litere din alfabetul roman (A-Z, Ă Â Î Ș Ț). Spatiiile vor fi eliminate."
    cleaned = ""
    for ch in text:
        if ch == " ":
            continue
        cleaned += to_upper_letter(ch)
    if cleaned == "":
        return False, "Mesajul trebuie sa contina cel putin o litera din alfabetul roman."
    return True, cleaned


def read_key():
    #Citeste cheia k1. Accepta doar intregi 1..30 (n-1)
    while True:
        raw = input("Introduceti cheia k (1-30): ").strip()
        if raw.isdigit():
            k = int(raw)
            if 1 <= k <= 30:
                return k
        print("Cheia trebuie sa fie un numar intreg din intervalul 1-30.")


def read_operation():
    #Citeste operatia: 1 = criptare, 2= decriptare
    while True:
        print("Alegeti operatia:")
        print("  1 - Criptare")
        print("  2 - Decriptare")
        raw = input("Optiune: ").strip()
        if raw == "1" or raw == "2":
            return raw
        print("Optiune invalida. Alegeti 1 sau 2.")


def read_message(prompt):
    #Citeste si valideaza mesajul / criptograma .
    while True:
        raw = input(prompt)
        ok, value = prepare_message(raw)
        if ok:
            return value
        print(value)


def read_keyword():
    #Citeste k2: doar litere romane, lungime cel putin 7.#
    while True:
        raw = input("Introduceti cheia 2 (minim 7 litere din alfabetul roman): ").strip()
        if " " in raw or len(raw) < 7:
            print("Cheia 2 trebuie sa contina doar litere romane, fara spatii, lungime >= 7.")
            continue
        valid = True
        for ch in raw:
            if not is_latin_letter(ch):
                valid = False
                break
        if not valid:
            print("Cheia 2 trebuie sa contina doar litere romane, fara spatii, lungime >= 7.")
            continue
        keyword = ""
        for ch in raw:
            keyword += to_upper_letter(ch)
        return keyword


def build_permuted_alphabet(keyword):
  #  Construieste alfabetul permutat:
    #- literele din k2, in ordine, fara duplicate
    #- apoi restul literelor alfabetului roman in ordine naturala
    perm = ""
    for ch in keyword:
        if letter_to_index(ch, perm) == -1:
            perm += ch
    for ch in ALPHABET:
        if letter_to_index(ch, perm) == -1:
            perm += ch
    return perm


def caesar_transform(text, k, alphabet, encrypt):
    #Cezar pe un alfabet dat de lungime N.
    #encrypt=True  ->(x + k) mod N
    #encrypt=False -> (x - k) mod N

    result = ""
    for ch in text:
        x = letter_to_index(ch, alphabet)
        if encrypt:
            y = (x + k) % N
        else:
            y = (x - k) % N
        result += index_to_letter(y, alphabet)
    return result


def run_one_key():
    #Meniu pentru Cezar clasic 1 cheie
    print("\n--- Cifrul Cezar (1 cheie) ---")
    print("Alfabet:", ALPHABET)
    op = read_operation()
    k = read_key()
    if op == "1":
        message = read_message("Introduceti mesajul: ")
        cipher = caesar_transform(message, k, ALPHABET, True)
        print("Mesaj prelucrat:", message)
        print("Criptograma:", cipher)
    else:
        cipher = read_message("Introduceti criptograma: ")
        message = caesar_transform(cipher, k, ALPHABET, False)
        print("Criptograma prelucrata:", cipher)
        print("Mesaj decriptat:", message)


def run_two_keys():
    #Meniu pentru Cezar + permutare 2 chei
    print("\n--- Cifrul Cezar + permutare (2 chei) ---")
    op = read_operation()
    k1 = read_key()
    k2 = read_keyword()
    alphabet = build_permuted_alphabet(k2)
    print("Alfabet permutat:", alphabet)
    if op == "1":
        message = read_message("Introduceti mesajul: ")
        cipher = caesar_transform(message, k1, alphabet, True)
        print("Mesaj prelucrat:", message)
        print("Criptograma:", cipher)
    else:
        cipher = read_message("Introduceti criptograma: ")
        message = caesar_transform(cipher, k1, alphabet, False)
        print("Criptograma prelucrata:", cipher)
        print("Mesaj decriptat:", message)


def main():
    while True:
        print()
        print("=================================")
        print("  Cifrul Cezar - Laborator 1")
        print("  Alfabet roman, n =", N)
        print("=================================")
        print("1. Cifrul Cezar (1 cheie)")
        print("2. Cifrul Cezar + permutare (2 chei)")
        print("3. Iesire")
        choice = input("Alegeti optiunea: ").strip()
        if choice == "1":
            run_one_key()
        elif choice == "2":
            run_two_keys()
        elif choice == "3":
            print("La revedere.")
            break
        else:
            print("Optiune invalida. Alegeti 1, 2 sau 3.")


if __name__ == "__main__":
    main()
