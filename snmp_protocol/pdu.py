"""
Implementare de baza a protocolului SNMPv1 - PDU-uri si mesaje.
Referinte:
[1] RFC 1157 - Simple Network Management Protocol (SNMP)
    https://datatracker.ietf.org/doc/html/rfc1157

[2] ITU-T X.690 - ASN.1 encoding rules (BER/DER)
    https://www.itu.int/rec/T-REC-X.690/en

[3] A Layman's Guide to a Subset of ASN.1, BER, and DER
    https://luca.ntop.org/Teaching/Appunti/asn1.html

"""

from snmp_protocol.ber import (
    ber_code_integer, ber_decode_integer,
    ber_code_octet, ber_decode_octet,
    ber_code_oid, ber_decode_oid,
    ber_code_sequence, ber_decode_sequence,
    ber_code_null, ber_decode_null,
)

# ============================================================================
# CONSTANTE SNMP (RFC 1157, Section 4)
# ============================================================================

# SNMP version (RFC 1157, Section 4.1)
SNMP_VERSION_1 = 0

# PDU types - Context-specific constructed tags (RFC 1157, Section 4.1.1)
PDU_GET_REQUEST = 0xA0  # [0] IMPLICIT - citeste valori
PDU_GET_NEXT_REQUEST = 0xA1  # [1] IMPLICIT - parcurge MIB-ul
PDU_GET_RESPONSE = 0xA2  # [2] IMPLICIT - raspuns de la agent
PDU_SET_REQUEST = 0xA3  # [3] IMPLICIT - modifica valori
PDU_TRAP = 0xA4  # [4] IMPLICIT - notificare asincrona

# Error status codes (RFC 1157, Section 4.1.3)
ERROR_NO_ERROR = 0  # Operatie reusita
ERROR_TOO_BIG = 1  # Raspunsul ar depasi limita de transport
ERROR_NO_SUCH_NAME = 2  # OID inexistent sau inaccesibil
ERROR_BAD_VALUE = 3  # Valoare invalida in SetRequest
ERROR_READ_ONLY = 4  # incercare de modificare a unui obiect read-only
ERROR_GEN_ERR = 5  # Eroare generala

# Generic trap types (RFC 1157, Section 4.1.6)
TRAP_COLD_START = 0  # Agent reinitializat (configuratie resetata)
TRAP_WARM_START = 1  # Agent reinitializat (configuratie pastrata)
TRAP_LINK_DOWN = 2  # Interfata de comunicatie cazuta
TRAP_LINK_UP = 3  # Interfata de comunicatie activata
TRAP_AUTH_FAILURE = 4  # Autentificare esuata (community string gresit)
TRAP_EGP_NEIGHBOR_LOSS = 5  # Pierdere vecin EGP
TRAP_ENTERPRISE_SPECIFIC = 6  # Trap specific aplicatiei (custom)


# ============================================================================
# FUNCTII AUXILIARE PENTRU LUNGIME BER (ITU-T X.690, Section 8.1.3)
# ============================================================================

def encode_length(length):
    """
    Codeaza lungimea in format BER (Basic Encoding Rules).

    Conform ITU-T X.690, Section 8.1.3:
    - Forma scurta: 0-127 -> un singur octet
    - Forma lunga: >=128 -> primul octet = 0x80 | nr_octeti_lungime

    Referinta: https://www.itu.int/rec/T-REC-X.690/en (Section 8.1.3)
    """
    if length < 128:
        return bytes([length])
    else:
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(length_bytes)]) + length_bytes


def decode_length(data, offset):
    """
    Decodeaza lungimea din format BER.

    Referinta: ITU-T X.690, Section 8.1.3
    """
    if offset >= len(data):
        raise ValueError("Date insuficiente pentru decodare lungime")

    first_byte = data[offset]
    offset += 1

    if first_byte < 128:
        return first_byte, offset
    elif first_byte == 0x80:
        raise ValueError("Forma indefinita de lungime nu este suportata in SNMP")
    else:
        num_bytes = first_byte & 0x7F
        if offset + num_bytes > len(data):
            raise ValueError("Date insuficiente pentru lungime in forma lunga")
        length_bytes = data[offset:offset + num_bytes]
        length = int.from_bytes(length_bytes, 'big')
        return length, offset + num_bytes


# ============================================================================
# CLASE DE DATE (RFC 1157, Section 4.1)
# ============================================================================

class VarBind:
    """
    Reprezinta o pereche (OID, valoare) - Variable Binding.

    Conform RFC 1157, Section 4.1.2:
    VarBind ::= SEQUENCE {
        name  ObjectName,
        value ObjectSyntax
    }
    
    Referinta: RFC 1157, Section 4.1.2
    https://datatracker.ietf.org/doc/html/rfc1157#section-4.1.2
    """

    def __init__(self, oid, value=None, value_type=None):
        # OID poate fi lista, tuplu sau string
        if isinstance(oid, (tuple, list)):
            self.oid = list(oid)
        else:
            # Daca e string, convertim la lista de int
            self.oid = [int(x) for x in str(oid).split('.')]

        self.value = value
        self.value_type = value_type  # 0x02 pentru INTEGER, 0x04 pentru OCTET, etc.

    def __repr__(self):
        oid_str = '.'.join(map(str, self.oid))
        return f"VarBind(oid={oid_str}, value={self.value})"

    def __eq__(self, other):
        if not isinstance(other, VarBind):
            return False
        return (self.oid == other.oid and
                self.value == other.value and
                self.value_type == other.value_type)


# ============================================================================
# FUNCTII DE ENCODARE/DECODARE VARBIND (RFC 1157, Section 4.1.2)
# ============================================================================

def encode_varbind(varbind):
    """
    Codeaza un VarBind in format BER.
    
    Structura conform RFC 1157:
    VarBind ::= SEQUENCE {
        name  OBJECT IDENTIFIER,
        value ObjectSyntax (INTEGER/OCTET STRING/NULL/etc.)
    }
    
    Referinta: RFC 1157, Section 4.1.2
    """
    # Codam OID-ul
    oid_encoded = ber_code_oid(varbind.oid)
    
    # Codam valoarea (daca nu e specificata, folosim NULL)
    if varbind.value is None:
        value_encoded = ber_code_null()
    elif varbind.value_type == 0x02:  # INTEGER
        value_encoded = ber_code_integer(varbind.value)
    elif varbind.value_type == 0x04:  # OCTET STRING
        if isinstance(varbind.value, str):
            value_encoded = ber_code_octet(varbind.value.encode('utf-8'))
        else:
            value_encoded = ber_code_octet(varbind.value)
    else:
        # Default: NULL
        value_encoded = ber_code_null()
    
    # Combinam OID + valoare intr-o secventa
    content = oid_encoded + value_encoded
    return ber_code_sequence(content)


def decode_varbind(data):
    """
    Decodeaza un VarBind din format BER.
    
    Returneaza: (VarBind object, nr_bytes_consumati)
    
    Referinta: RFC 1157, Section 4.1.2
    """
    # Verificam ca e SEQUENCE
    if not data or data[0] != 0x30:
        raise ValueError("VarBind trebuie sa fie SEQUENCE")
    
    # Extragem continutul secventei
    content = ber_decode_sequence(data)
    
    # Decodam OID-ul
    oid = ber_decode_oid(content)
    
    # Calculam cate bytes a consumat OID-ul
    oid_encoded = ber_code_oid(oid)
    oid_len = len(oid_encoded)
    
    # Decodam valoarea
    value_data = content[oid_len:]
    if not value_data:
        raise ValueError("VarBind fara valoare")
    
    value_type = value_data[0]
    
    if value_type == 0x02:  # INTEGER
        value = ber_decode_integer(value_data)
    elif value_type == 0x04:  # OCTET STRING
        value = ber_decode_octet(value_data)
    elif value_type == 0x05:  # NULL
        value = None
    else:
        # Tip necunoscut, returnam None
        value = None
    
    varbind = VarBind(oid, value, value_type)
    
    # Calculam total bytes consumati (tag + length + content)
    total_len = 2 + len(content)  # 0x30 + length byte + content
    
    return varbind, total_len


def encode_varbind_list(varbinds):
    """
    Codeaza o lista de VarBind-uri intr-o SEQUENCE.
    
    Referinta: RFC 1157, Section 4.1.2
    """
    encoded_varbinds = b''
    for vb in varbinds:
        encoded_varbinds += encode_varbind(vb)
    
    return ber_code_sequence(encoded_varbinds)


def decode_varbind_list(data):
    """
    Decodeaza o lista de VarBind-uri dintr-o SEQUENCE.
    
    Returneaza: lista de VarBind objects
    
    Referinta: RFC 1157, Section 4.1.2
    """
    # Verificam ca e SEQUENCE
    if not data or data[0] != 0x30:
        raise ValueError("VarBindList trebuie sa fie SEQUENCE")
    
    # Extragem continutul
    content = ber_decode_sequence(data)
    
    varbinds = []
    offset = 0
    
    while offset < len(content):
        vb_data = content[offset:]
        varbind, consumed = decode_varbind(vb_data)
        varbinds.append(varbind)
        offset += consumed
    
    return varbinds


# ============================================================================
# FUNCTII ENCODARE PDU-URI OPERATIONALE (RFC 1157, Section 4.1.1)
# Get/GetNext/Set/Response au aceeasi structura
# ============================================================================

def encode_pdu_get_request(request_id, varbinds):
    """
    Codeaza un PDU de tip GetRequest.
    
    Structura conform RFC 1157, Section 4.1.1:
    GetRequest-PDU ::= [0] IMPLICIT PDU
    PDU ::= SEQUENCE {
        request-id INTEGER,
        error-status INTEGER,
        error-index INTEGER,
        variable-bindings VarBindList
    }
    
    Referinta: RFC 1157, Section 4.1.1
    https://datatracker.ietf.org/doc/html/rfc1157#section-4.1.1
    """
    # Pentru GetRequest: error-status = 0, error-index = 0
    content = b''
    content += ber_code_integer(request_id)
    content += ber_code_integer(ERROR_NO_ERROR)  # error-status
    content += ber_code_integer(0)  # error-index
    content += encode_varbind_list(varbinds)
    
    # Encodam lungimea
    length_encoded = encode_length(len(content))
    
    # Returnam: tag (0xA0) + lungime + content
    return bytes([PDU_GET_REQUEST]) + length_encoded + content


def encode_pdu_get_next_request(request_id, varbinds):
    """
    Codeaza un PDU de tip GetNextRequest.
    
    Structura identica cu GetRequest, dar cu tag diferit (0xA1).
    
    Referinta: RFC 1157, Section 4.1.1
    """
    content = b''
    content += ber_code_integer(request_id)
    content += ber_code_integer(ERROR_NO_ERROR)
    content += ber_code_integer(0)
    content += encode_varbind_list(varbinds)
    
    length_encoded = encode_length(len(content))
    return bytes([PDU_GET_NEXT_REQUEST]) + length_encoded + content


def encode_pdu_set_request(request_id, varbinds):
    """
    Codeaza un PDU de tip SetRequest.
    
    Structura identica cu GetRequest, dar cu tag diferit (0xA3).
    
    Referinta: RFC 1157, Section 4.1.1
    """
    content = b''
    content += ber_code_integer(request_id)
    content += ber_code_integer(ERROR_NO_ERROR)
    content += ber_code_integer(0)
    content += encode_varbind_list(varbinds)
    
    length_encoded = encode_length(len(content))
    return bytes([PDU_SET_REQUEST]) + length_encoded + content


def encode_pdu_get_response(request_id, error_status, error_index, varbinds):
    """
    Codeaza un PDU de tip GetResponse.
    
    Structura identica cu GetRequest, dar permite error_status si error_index.
    Tag: 0xA2
    
    Referinta: RFC 1157, Section 4.1.1
    """
    content = b''
    content += ber_code_integer(request_id)
    content += ber_code_integer(error_status)
    content += ber_code_integer(error_index)
    content += encode_varbind_list(varbinds)
    
    length_encoded = encode_length(len(content))
    return bytes([PDU_GET_RESPONSE]) + length_encoded + content


# ============================================================================
# FUNCTII DECODARE PDU-URI OPERATIONALE (RFC 1157, Section 4.1.1)
# ============================================================================

def decode_pdu_operational(data):
    """
    Decodeaza un PDU operational (Get/GetNext/Set/Response).
    
    Returneaza: dict cu campurile PDU-ului
    {
        'pdu_type': 0xA0/0xA1/0xA2/0xA3,
        'request_id': int,
        'error_status': int,
        'error_index': int,
        'varbinds': [VarBind, ...]
    }
    
    Referinta: RFC 1157, Section 4.1.1
    """
    if not data:
        raise ValueError("Date PDU goale")
    
    pdu_type = data[0]
    if pdu_type not in [PDU_GET_REQUEST, PDU_GET_NEXT_REQUEST, 
                        PDU_SET_REQUEST, PDU_GET_RESPONSE]:
        raise ValueError(f"Tip PDU operational invalid: {hex(pdu_type)}")
    
    # Decodam lungimea
    length, offset = decode_length(data, 1)
    
    # Extragem continutul
    content = data[offset:offset + length]
    
    # Decodam campurile
    pos = 0
    
    # request-id
    request_id = ber_decode_integer(content[pos:])
    req_id_encoded = ber_code_integer(request_id)
    pos += len(req_id_encoded)
    
    # error-status
    error_status = ber_decode_integer(content[pos:])
    err_stat_encoded = ber_code_integer(error_status)
    pos += len(err_stat_encoded)
    
    # error-index
    error_index = ber_decode_integer(content[pos:])
    err_idx_encoded = ber_code_integer(error_index)
    pos += len(err_idx_encoded)
    
    # variable-bindings
    varbinds_data = content[pos:]
    varbinds = decode_varbind_list(varbinds_data)
    
    return {
        'pdu_type': pdu_type,
        'request_id': request_id,
        'error_status': error_status,
        'error_index': error_index,
        'varbinds': varbinds
    }


# ============================================================================
# FUNCTII ENCODARE/DECODARE TRAP PDU (RFC 1157, Section 4.1.6)
# ============================================================================

def encode_pdu_trap(enterprise_oid, agent_addr, generic_trap, specific_trap, 
                    timestamp, varbinds):
    """
    Codeaza un PDU de tip Trap.
    
    Structura conform RFC 1157, Section 4.1.6:
    Trap-PDU ::= [4] IMPLICIT SEQUENCE {
        enterprise OBJECT IDENTIFIER,
        agent-addr NetworkAddress (IpAddress),
        generic-trap INTEGER,
        specific-trap INTEGER,
        time-stamp TimeTicks,
        variable-bindings VarBindList
    }
    
    agent_addr: string IP (ex: "192.168.1.10")
    timestamp: integer (TimeTicks - sutimi de secunda de la pornire)
    
    Referinta: RFC 1157, Section 4.1.6
    https://datatracker.ietf.org/doc/html/rfc1157#section-4.1.6
    """
    content = b''
    
    # enterprise OID
    content += ber_code_oid(enterprise_oid)
    
    # agent-addr: NetworkAddress = [APPLICATION 0] IMPLICIT OCTET STRING
    # Codam IP-ul ca OCTET STRING (4 bytes)
    ip_parts = agent_addr.split('.')
    ip_bytes = bytes([int(x) for x in ip_parts])
    # Tag pentru IpAddress: [APPLICATION 0] = 0x40
    content += bytes([0x40, 0x04]) + ip_bytes
    
    # generic-trap
    content += ber_code_integer(generic_trap)
    
    # specific-trap
    content += ber_code_integer(specific_trap)
    
    # time-stamp: TimeTicks = [APPLICATION 3] IMPLICIT INTEGER
    # Tag pentru TimeTicks: 0x43
    timestamp_encoded = ber_code_integer(timestamp)
    # Inlocuim tag-ul 0x02 cu 0x43
    timestamp_encoded = bytes([0x43]) + timestamp_encoded[1:]
    content += timestamp_encoded
    
    # variable-bindings
    content += encode_varbind_list(varbinds)
    
    # Encodam lungimea
    length_encoded = encode_length(len(content))
    
    return bytes([PDU_TRAP]) + length_encoded + content


def decode_pdu_trap(data):
    """
    Decodeaza un PDU de tip Trap.
    
    Returneaza: dict cu campurile Trap-ului
    {
        'pdu_type': 0xA4,
        'enterprise': [1, 3, 6, ...],
        'agent_addr': "192.168.1.10",
        'generic_trap': int,
        'specific_trap': int,
        'timestamp': int,
        'varbinds': [VarBind, ...]
    }
    
    Referinta: RFC 1157, Section 4.1.6
    """
    if not data or data[0] != PDU_TRAP:
        raise ValueError("Nu este un PDU Trap valid")
    
    # Decodam lungimea
    length, offset = decode_length(data, 1)
    
    # Extragem continutul
    content = data[offset:offset + length]
    
    pos = 0
    
    # enterprise OID
    enterprise = ber_decode_oid(content[pos:])
    enterprise_encoded = ber_code_oid(enterprise)
    pos += len(enterprise_encoded)
    
    # agent-addr: IpAddress [APPLICATION 0]
    if content[pos] != 0x40:
        raise ValueError("Agent address trebuie sa fie IpAddress (tag 0x40)")
    pos += 1  # skip tag
    addr_len = content[pos]
    pos += 1
    ip_bytes = content[pos:pos + addr_len]
    agent_addr = '.'.join(map(str, ip_bytes))
    pos += addr_len
    
    # generic-trap
    generic_trap = ber_decode_integer(content[pos:])
    gen_trap_encoded = ber_code_integer(generic_trap)
    pos += len(gen_trap_encoded)
    
    # specific-trap
    specific_trap = ber_decode_integer(content[pos:])
    spec_trap_encoded = ber_code_integer(specific_trap)
    pos += len(spec_trap_encoded)
    
    # time-stamp: TimeTicks [APPLICATION 3] (tag 0x43)
    if content[pos] != 0x43:
        raise ValueError("Timestamp trebuie sa fie TimeTicks (tag 0x43)")
    # Inlocuim temporar tag-ul cu 0x02 pentru a folosi ber_decode_integer
    timestamp_data = bytes([0x02]) + content[pos + 1:pos + 10]  # aproximativ
    timestamp = ber_decode_integer(timestamp_data)
    # Calculam cate bytes a consumat
    timestamp_encoded = ber_code_integer(timestamp)
    pos += len(timestamp_encoded)
    
    # variable-bindings
    varbinds_data = content[pos:]
    varbinds = decode_varbind_list(varbinds_data)
    
    return {
        'pdu_type': PDU_TRAP,
        'enterprise': enterprise,
        'agent_addr': agent_addr,
        'generic_trap': generic_trap,
        'specific_trap': specific_trap,
        'timestamp': timestamp,
        'varbinds': varbinds
    }


# ============================================================================
# FUNCTII MESAJ SNMP COMPLET (RFC 1157, Section 4.1)
# ============================================================================

def encode_snmp_message(community, pdu_data):
    """
    Codeaza un mesaj SNMP complet (version + community + PDU).
    
    Structura conform RFC 1157, Section 4.1:
    Message ::= SEQUENCE {
        version INTEGER {version-1(0)},
        community OCTET STRING,
        data ANY (PDU)
    }
    
    community: string (ex: "public")
    pdu_data: bytes (PDU deja encodat)
    
    Referinta: RFC 1157, Section 4.1
    https://datatracker.ietf.org/doc/html/rfc1157#section-4.1
    """
    content = b''
    
    # version (SNMPv1 = 0)
    content += ber_code_integer(SNMP_VERSION_1)
    
    # community string
    content += ber_code_octet(community.encode('utf-8'))
    
    # PDU
    content += pdu_data
    
    # Invelim totul intr-o SEQUENCE
    return ber_code_sequence(content)


def decode_snmp_message(data):
    """
    Decodeaza un mesaj SNMP complet.
    
    Returneaza: dict cu campurile mesajului
    {
        'version': int,
        'community': str,
        'pdu': dict (rezultatul din decode_pdu_operational sau decode_pdu_trap)
    }
    
    Referinta: RFC 1157, Section 4.1
    """
    if not data or data[0] != 0x30:
        raise ValueError("Mesajul SNMP trebuie sa fie SEQUENCE")
    
    # Extragem continutul secventei
    content = ber_decode_sequence(data)
    
    pos = 0
    
    # version
    version = ber_decode_integer(content[pos:])
    version_encoded = ber_code_integer(version)
    pos += len(version_encoded)
    
    if version != SNMP_VERSION_1:
        raise ValueError(f"Versiune SNMP nesuportata: {version}")
    
    # community
    community_bytes = ber_decode_octet(content[pos:])
    community = community_bytes.decode('utf-8')
    community_encoded = ber_code_octet(community_bytes)
    pos += len(community_encoded)
    
    # PDU
    pdu_data = content[pos:]
    pdu_type = pdu_data[0]
    
    if pdu_type == PDU_TRAP:
        pdu = decode_pdu_trap(pdu_data)
    else:
        pdu = decode_pdu_operational(pdu_data)
    
    return {
        'version': version,
        'community': community,
        'pdu': pdu
    }