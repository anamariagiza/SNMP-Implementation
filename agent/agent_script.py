import socket
import threading
import time
from agent.mib import *
from snmp_protocol.ber import *
from snmp_protocol.pdu import *

#Configurari initiale
AGENT_IP = "127.0.0.1"
AGENT_PORT = 16100
MANAGER_IP = "127.0.0.1"
MANAGER_TRAP_PORT = 16200 #Portul pe care se trimit trap-urile catre manager
ENCODING = "utf-8"


def get_next_oid(current_oid: str): #are scopul de a genera urmatorul element din mib, pt cererile de tip GETNEXT

    #se extrag elementele din mib si se sorteaza lexicografic
    sorted_oids = sorted(
        MIB.keys(),
        key=lambda oid: [int(part) for part in oid.split(".") if part] #sparge oid-ul in mai multe parti, folosind "." ca separator, iar mai apoi converteste informatia in intreg
    )

    try:
        current_index = sorted_oids.index(current_oid) #cautam indexul oid_ului curent
        if current_index + 1 < len(sorted_oids): #verificam daca mai exista alt oid
            next_oid = sorted_oids[current_index + 1]
            return next_oid
        else:
            return None

    except ValueError:
        raise KeyError(f"OID inexistent in MIB: {current_oid}") #daca oid-ul curent nu exista aruncam o eroare

#...???...
def send_trap(oid, value):
    try:
        trap_pdu = encode_pdu_trap(
            enterprise_oid=[1, 3, 6, 1, 4, 1, 99999],
            agent_addr=AGENT_IP,
            generic_trap=6,  # enterpriseSpecific
            specific_trap=1,
            timestamp=int(time.time()),
            varbinds=[VarBind(oid, value,0x02)]
        )
        message = encode_snmp_message("public", trap_pdu)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(message, (MANAGER_IP, MANAGER_TRAP_PORT))
    except Exception as e:
        print(f"[WARN] send_trap: {e}")

#monitorizare si trimitere trap-uri
def checks():

    OID_CPU = "1.3.6.1.4.1.99999.2.1.0"
    OID_MEM = "1.3.6.1.4.1.99999.2.2.0"
    OID_TEMP = "1.3.6.1.4.1.99999.2.4.0"

    while True:
        try:
            cpu_value = int(get_value(OID_CPU))
            mem_value = int(get_value(OID_MEM))
            temp_value = int(get_value(OID_TEMP))

            if cpu_value > praguri_maxime["cpuMax"]:
                send_trap(OID_CPU,cpu_value)

            if mem_value > praguri_maxime["memMax"]:
                send_trap(OID_MEM,mem_value)

            if temp_value > praguri_maxime["tempMax"]:
                send_trap(OID_TEMP,temp_value)

        except Exception as e:
            print(f"[WARN checks] {e}")

        time.sleep(5)

def process_request(data):
    snmp = decode_snmp_message(data)
    pdu = snmp["pdu"]

    request_id = pdu["request_id"]
    response_varbinds = []

    for varbind in pdu["varbinds"]:
        oid = ".".join(map(str, varbind.oid))
        error_status = ERROR_NO_ERROR
        error_index = 0
        value = None

        try:
            if pdu["pdu_type"] == PDU_GET_REQUEST:
                value = get_value(oid)
                print(f"[AGENT] GET OID {oid} => {value}")

            elif pdu["pdu_type"] == PDU_GET_NEXT_REQUEST:
                next_oid = get_next_oid(oid)
                if not next_oid:
                    raise KeyError("End of MIB")
                oid = next_oid
                value = get_value(oid)

            elif pdu["pdu_type"] == PDU_SET_REQUEST:
                set_tempUnit(oid, varbind.value)
                value = get_value(oid)

            else:
                error_status = ERROR_GEN_ERR

        except KeyError:
            error_status = ERROR_NO_SUCH_NAME
            error_index = 1

        response_varbinds.append(VarBind(oid, value if value is not None else 0, 0x02))

        for vb in response_varbinds:
            print(
                f"[DEBUG-AGENT] VarBind trimis: OID={vb.oid} | Value={vb.value} | Type={type(vb.value)} | BER Type={vb.value_type}")

    response_pdu = encode_pdu_get_response(
        request_id=request_id,
        error_status=ERROR_NO_ERROR,  # eroarea generala se poate gestiona la nivel de fiecare varbind daca vrei
        error_index=0,
        varbinds=response_varbinds
    )
    return encode_snmp_message("public", response_pdu)



def start_agent():

    #ACTIVAM FUNCTIA check() in thread
    monitor_thread = threading.Thread(target=checks, daemon=True)
    monitor_thread.start()

    # Socket UDP pentru agent + Pornire Agent
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        try:
            udp_socket.bind((AGENT_IP, AGENT_PORT)) #leaga socket-ul de portul pe care agentul primeste cereri
            print(f"[AGENT] UDP pornit pe {AGENT_IP}:{AGENT_PORT} se pot trimtie comenzi: GET / GETNEXT / SET")

            while True:
                data, addr = udp_socket.recvfrom(4096) #cereri primite de la manager
                try:

                    response = process_request(data)
                    udp_socket.sendto(response,addr)

                except Exception as e:
                    response_bytes = ber_code_octet(f"ERROR {e}".encode(ENCODING))

        except Exception as e:
            print(f"[ERROR start_agent-socket] {e}")


if __name__ == "__main__":
        start_agent()
