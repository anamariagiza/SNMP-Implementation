from snmp_protocol.ber import *
from agent.sensors import *
import time

def main():

    valori_test = [127, 128, 256]

    for v in valori_test:
        encoded = ber_code_integer(v)
        decoded = ber_decode_integer(encoded)
        print(f"Val initiala: {v}")
        print(f"Intreg BER: {encoded.hex().upper()}")
        print(f"Intreg Decodificat BER: {decoded}")
        print()

    # Codificare/decodificare octet
    msg = b'Hello'
    encoded = ber_code_octet(msg)
    print(f"Octet BER:{encoded.hex()}")
    decoded = ber_decode_octet(encoded)
    print(f"Octet Decodificat BER:{decoded}")
    print()

    #Codificare / decodificare null
    encoded = ber_code_null()
    print(f"Null BER:{encoded.hex()}")
    decoded = ber_decode_null(encoded)
    print(f"Null Decodifficat BER:{decoded}")
    print()

    #Codificare / decodificare secventa
    data = b'\x02\x01\x05\x04\x01\x41'
    encoded = ber_code_sequence(data)
    print(f"Sequence BER:{encoded.hex()}")
    decoded = ber_decode_sequence(encoded)
    print(f"Sequence Decodificat BER:{decoded.hex()}")
    print()

    #Codificare / decodificare OID
    oid = [1, 3, 6, 1, 4, 1, 99999, 2, 1, 0]
    encoded = ber_code_oid(oid)
    print("Oid BER codificat:", encoded.hex())
    decoded = ber_decode_oid(encoded)
    print("Oid Decodificat BER:", decoded)
    print()

    for i in range(3):
        cpu = cpu_load_procent()
        mem = mem_used_MiB()
        disk = disk_used_MiB()
        nr_proc = proc_counter()
        print(f"Iteratia {i + 1}: Cpu este utilizat in proportie de {cpu}%, memoria utilizata = {mem}MiB, utilizare disk = {disk}MiB, nr. procese active = {nr_proc}")
        time.sleep(1)  # asteapta 1 secunda intre masuratori

if __name__ == "__main__":
    main()
