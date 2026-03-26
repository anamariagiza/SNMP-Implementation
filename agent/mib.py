from agent.sensors import *

# praguri fixe
praguri_maxime = {
    "cpuMax": 85,
    "memMax": 4096,
    "tempMax": 70
}

# unitatea de masura pt temperatura - 0 = grade C, 1 = grade F, 2 = grade K
temp_unit = 0

def modificare_unit_temp():

    t = cpu_temp_c()
    if temp_unit == 1:
        return int(t * 9/5 + 32) #temp in grade F
    elif temp_unit == 2:
        return int(t + 273.15) #temp in grade K
    return t

# MIB principal
MIB = {
    "1.3.6.1.4.1.99999.2.1.0": {"name": "cpuLoad", "type": "INTEGER", "unit": "%", "value": cpu_load_procent},
    "1.3.6.1.4.1.99999.2.2.0": {"name": "memoryUsed", "type": "INTEGER", "unit": "MiB", "value": mem_used_MiB},
    "1.3.6.1.4.1.99999.2.3.0": {"name": "diskUsed", "type": "INTEGER", "unit": "MiB", "value": disk_used_MiB},
    "1.3.6.1.4.1.99999.2.4.0": {"name": "tempValue", "type": "INTEGER", "unit": "°C", "value": modificare_unit_temp},
    "1.3.6.1.4.1.99999.2.5.0": {"name": "tempUnit", "type": "INTEGER", "unit": "0 = C, 1 = F , 2 = K}", "value": temp_unit},
    "1.3.6.1.4.1.99999.2.6.0": {"name": "procCount", "type": "INTEGER", "unit": "n", "value": proc_counter},

    # trap-uri
    "1.3.6.1.4.1.99999.3.1.0": {"name": "cpuMax", "type": "INTEGER", "unit": "%", "value": praguri_maxime["cpuMax"]},
    "1.3.6.1.4.1.99999.3.2.0": {"name": "memMax", "type": "INTEGER", "unit": "MiB", "value": praguri_maxime["memMax"]},
    "1.3.6.1.4.1.99999.3.3.0": {"name": "tempMax", "type": "INTEGER", "unit": "°C", "value": praguri_maxime["tempMax"]},
}

def get_value(oid):

    if oid not in MIB: #se verifica daca elementul exista in dictionar
        raise KeyError(f"OID-ul nu se afla in MIB: {oid}")
    v = MIB[oid]["value"] #din dictionar, pt oid-ul dat se extrage campul "value"

    if callable(v): #daca in "value" avem o functie aceasta se va apela
        return v()
    else:
        return v #daca in "value" avem un intreg acesta se returneaza


def set_tempUnit(oid, val): #functie ce ne ajuta la alegerea unitatii de masura pt temp
    global temp_unit
    if oid == "1.3.6.1.4.1.99999.2.5.0": #se verifica ca oid-ul sa fie cel pt schimbarea unitatii
        temp_unit = int(val)
        MIB[oid]["value"] = temp_unit
    else:
        raise ValueError("OID-ul nu este cel pt tempUnit : 1.3.6.1.4.1.99999.2.5.0")
