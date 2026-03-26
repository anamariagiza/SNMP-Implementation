
#CODIFICARE / DECODIFICARE INTREG

def ber_code_integer(value: int) -> bytes:

    if value == 0:
        coded_value = b'\x00' #daca valoarea este 0, se codifica direct
    else:
        nr_octeti = (value.bit_length()+7)//8 #se calculeaza nr de octeti necesari reprezentarii
        coded_value = value.to_bytes(nr_octeti, byteorder='big') #valoare devine o secventa de octeti, cu dimensiunea calculata si in format bigendian

        if coded_value[0] & 0x80: #verifica daca cel mai semnificativ bit e 1
            coded_value = b'\x00' + coded_value #se mai adauga un octet 0 in fata valorii pt a elimina cazul de valoare negativa

    length = len(coded_value) #se extrage lungimea in octeti a valorii

    return bytes([0x02, length]) + coded_value #se returneaza o secventa de octeti, la care se concateneaza valoarea


def ber_decode_integer(data: bytes) -> int:

    if not data or data[0] != 0x02:
        raise ValueError("! Datele nu reprezinta un INTEGER de forma BER !")

    length = data[1] #se extrage lungimea

    value_bytes = data[2: 2 + length] #se extrage valoarea din secventa

    if len(value_bytes) > 1 and value_bytes[0] == 0x00: #daca exista un octet 0 adaugat pt cazul de val negativa, il stergem
        value_bytes = value_bytes[1:]

    return int.from_bytes(value_bytes, byteorder='big', signed=False) #se converteste valoare in int


#CODIFICAREA/DECODIFICAREA unui Octet String

def ber_code_octet(data: bytes) -> bytes:

    length = len(data) #se determina numarul de octeti

    return bytes([0x04, length]) + data #se returneaza o secventa de octeti(contine tipul, lungimea) la care sa concatenat o alta secventa ce contine val propriu-zisa

def ber_decode_octet(data: bytes) -> bytes:

    if not data or data[0] != 0x04:
        raise ValueError("! Datele nu reprezintă un OCTET de forma BER !")

    length = data[1] #se extrage lungimea

    value_bytes = data[2: 2 + length] #se extrage valoarea

    return value_bytes


#CODIFICARE/DECODIFICARE NULL

def ber_code_null() -> bytes:
    return b'\x05\x00' #se returneaza un NULL codificat BER de forma : 05 00

def ber_decode_null(data: bytes):

    if not data:
        raise ValueError("! Datele nu reprezinta un NULL de forma ber")

    if len(data)!=2 or data[0] != 0x05 or data[1] != 0x00:
        raise ValueError("! Datele nu reprezinta un NULL de forma ber")

    return None


#CODIFICARE/DECODIFIACRE SECVENTA

def ber_code_sequence(data: bytes) -> bytes:

    length = len(data) #se determina lungimea secventei

    return bytes([0x30,length]) + data #se returneaza o secventa de octeti, de forma : 30 length data

def ber_decode_sequence(data: bytes) -> bytes:

    if not data or data[0] != 0x30:
        raise ValueError("! Datele nu reprezinta o secventa de forma ber")

    length = data[1] #extragem lungimea secventei

    value_bytes = data[2: 2 + length] #extragem continutul secventei

    return value_bytes


#CODIFICAREA/DECODIFICAREA UNUI OID

def ber_code_oid(oid: list[int]) -> bytes:

    if len(oid) < 2: # Verificam ca Oid sa aiba macar 2 elem, pt a putea alcatui primul octet
        raise ValueError("OID-ul trebuie sa aiba cel putin 2 sub-identificatori")

    byte_1 = 40 * oid[0] + oid[1] #primul octet reprezinta o combinatie intre primele 2 elem, conform regulei

    encoded = [byte_1] #se initializeaza lista cu primul element

    for i in oid[2:]: #se parcurg urmatoarele elemente

        if i == 0: #daca identificatorul este 0, se adauga direct
            encoded.append(0)
            continue

        temp = []
        while i > 0: #intregul se converteste in baza 128(2ˆ7)
            temp.insert(0, i & 0x7F) #vom lua octeti ce vor contine doar 7 biti, bitul 1 fiind rezervat pt MSB
            i >>= 7 #se elimina cei 7 biti extrasi

        for j in range(0, len(temp) - 1):
            temp[j] |= 0x80 #pt octetii ce mai au alti octeti dupa ei in lista TEMP, bitul 1 devine 1

        encoded.extend(temp) #elementele codate conform BER se adauga in lista

    length = len(encoded) #lungimea oid

    return bytes([0x06, length]) + bytes(encoded) #se returneaza secventa de octeti


def ber_decode_oid(data: bytes) -> list[int]:

    if not data or data[0] != 0x06:
        raise ValueError("! Datele nu reprezinta un Oid in format BER !")

    length = data[1]                    # extragem lungimea
    value_bytes = data[2:2 + length]    # extragem continutul efectiv

    if len(value_bytes) != length:
        raise ValueError("Lungimea declarata nu corespunde datelor efective")

    nr1 = value_bytes[0]
    ident_1= nr1 // 40 #primul identificator
    ident_2 = nr1 % 40 #al doilea identificator
    oid = [ident_1, ident_2]

    val = 0
    for i in value_bytes[1:]:
        val = val << 7 #continutul se muta la stanga pt a face loc urm 7 biti
        val = val | (i & 0x7F)  #se adauga cei 7 biti
        if (i & 0x80) == 0: #daca MSB este 0, inseamna ca nu mai urmeaza niciun element, iar secventa s-a incheiat
            oid.append(val)
            val = 0

    return oid