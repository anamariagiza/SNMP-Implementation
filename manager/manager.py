"""
Manager SNMP - Logica business pentru gestionarea agentilor SNMP.

Acest modul contine clasa SNMPManager si constantele necesare,
separat de interfata utilizator pentru o mai buna modularitate.

Referinte:
[1] RFC 1157 - Simple Network Management Protocol (SNMP)
    https://datatracker.ietf.org/doc/html/rfc1157

Functionalitati:
- Trimitere GetRequest, GetNextRequest, SetRequest catre agenti
- Receptie trap-uri (UDP 162) in thread separat
- Auto-refresh periodic al valorilor
- Export CSV al datelor colectate
"""

import csv
import os
import socket
import sys
import threading
import time
from datetime import datetime

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Adaugam caile pentru import-uri
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from snmp_protocol.pdu import *

# Console global pentru Rich (folosit pentru display-uri)
console = Console()


# ============================================================================
# CONFIGURATIE GLOBALA
# ============================================================================

MANAGER_TRAP_PORT = 16200  # Port pentru trap-uri
AGENT_PORT = 16100  # Port agenti
TIMEOUT = 5  # Timeout cereri (secunde)
DEFAULT_COMMUNITY = "public"

# OID-uri resurse monitorizate
OID_CPU = [1, 3, 6, 1, 4, 1, 99999, 2, 1, 0]
OID_MEMORY = [1, 3, 6, 1, 4, 1, 99999, 2, 2, 0]
OID_DISK = [1, 3, 6, 1, 4, 1, 99999, 2, 3, 0]
OID_TEMP_VALUE = [1, 3, 6, 1, 4, 1, 99999, 2, 4, 0]
OID_TEMP_UNIT = [1, 3, 6, 1, 4, 1, 99999, 2, 5, 0]
OID_PROC_COUNT = [1, 3, 6, 1, 4, 1, 99999, 2, 6, 0]

# OID-uri praguri
OID_CPU_MAX = [1, 3, 6, 1, 4, 1, 99999, 3, 1, 0]
OID_MEM_MAX = [1, 3, 6, 1, 4, 1, 99999, 3, 2, 0]
OID_TEMP_MAX = [1, 3, 6, 1, 4, 1, 99999, 3, 3, 0]

# Mapare OID -> nume
OID_NAMES = {
    tuple(OID_CPU): "CPU",
    tuple(OID_MEMORY): "Memory",
    tuple(OID_DISK): "Disk",
    tuple(OID_TEMP_VALUE): "Temperature",
    tuple(OID_TEMP_UNIT): "Temp Unit",
    tuple(OID_PROC_COUNT): "Processes",
}

# Unitati temperatura
TEMP_UNITS = {0: "°C", 1: "°F", 2: "K"}


# ============================================================================
# CLASA SNMP MANAGER
# ============================================================================

class SNMPManager:
    """
    Manager SNMP care gestioneaza comunicarea cu agentii.

    Responsabilitati:
    - Trimitere cereri Get/GetNext/Set catre agenti
    - Receptie trap-uri de la agenti
    - Auto-refresh periodic

    Referinta: RFC 1157, Section 4
    """

    def __init__(self, community=DEFAULT_COMMUNITY):
        """
        Initializeaza managerul SNMP.
        
        Args:
            community: Community string pentru autentificare (default: "public")
        """
        self.community = community
        self.agents = []  # Lista (ip, port)
        self.request_id = 1
        self.trap_log = []  # Log trap-uri
        self.current_values = {}  # Valori curente
        self.running = False

        # Socket cereri
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(TIMEOUT)

        # Socket trap-uri
        self.trap_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.trap_sock.bind(('0.0.0.0', MANAGER_TRAP_PORT))

        # Thread-uri
        self.trap_thread = None
        self.refresh_thread = None
        self.refresh_interval = 0

    def add_agent(self, ip, port=AGENT_PORT):
        """
        Adauga un agent la lista.
        
        Args:
            ip: Adresa IP a agentului
            port: Port UDP al agentului (default: 16100)
        """
        agent_addr = (ip, port)
        if agent_addr not in self.agents:
            self.agents.append(agent_addr)
            console.print(f"[green]Agent adaugat: {ip}:{port}[/green]")
        else:
            console.print(f"[yellow]Agent {ip}:{port} exista deja[/yellow]")

    def remove_agent(self, ip, port=AGENT_PORT):
        """
        Sterge un agent din lista.
        
        Args:
            ip: Adresa IP a agentului
            port: Port UDP al agentului (default: 16100)
        """
        agent_addr = (ip, port)
        if agent_addr in self.agents:
            self.agents.remove(agent_addr)
            console.print(f"[green]Agent sters: {ip}:{port}[/green]")
        else:
            console.print(f"[yellow]Agent {ip}:{port} nu exista[/yellow]")

    def get_next_request_id(self):
        """
        Genereaza request ID unic.
        
        Returns:
            int: Request ID incremental
        """
        req_id = self.request_id
        self.request_id += 1
        return req_id

    def send_get_request(self, agent_addr, oids):
        """
        Trimite GetRequest catre agent.
        
        Args:
            agent_addr: Tuplu (ip, port) al agentului
            oids: Lista de OID-uri de interogat
        
        Returns:
            dict: Mapare OID -> valoare sau None daca eroare
        """
        try:
            varbinds = [VarBind(oid) for oid in oids]
            request_id = self.get_next_request_id()
            pdu_data = encode_pdu_get_request(request_id, varbinds)
            message = encode_snmp_message(self.community, pdu_data)

            self.sock.sendto(message, agent_addr)
            response_data, addr = self.sock.recvfrom(4096)

            response = decode_snmp_message(response_data)
            pdu_response = response['pdu']

            if pdu_response['error_status'] != ERROR_NO_ERROR:
                console.print(f"[red]Eroare agent: status={pdu_response['error_status']}[/red]")
                return None

            result = {}
            for vb in pdu_response['varbinds']:
                oid_tuple = tuple(vb.oid)
                result[oid_tuple] = vb.value

            return result

        except socket.timeout:
            console.print(f"[red]Timeout de la {agent_addr[0]}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Eroare send_get_request: {e}[/red]")
            return None
        
    def send_get_next_request(self, agent_addr, oid):
        """
        Trimite GetNextRequest catre agent pentru a obtine urmatorul OID.
        
        Args:
            agent_addr: Tuplu (ip, port) al agentului
            oid: OID curent (lista de intregi)
        
        Returns:
            dict: Mapare OID urmator -> valoare sau None daca eroare
        """
        try:
            varbind = VarBind(oid)
            request_id = self.get_next_request_id()
            pdu_data = encode_pdu_get_next_request(request_id, [varbind])
            message = encode_snmp_message(self.community, pdu_data)
            
            self.sock.sendto(message, agent_addr)
            response_data, addr = self.sock.recvfrom(4096)
            
            response = decode_snmp_message(response_data)
            pdu_response = response['pdu']
            
            if pdu_response['error_status'] != ERROR_NO_ERROR:
                console.print(f"[red]Eroare GetNext: status={pdu_response['error_status']}[/red]")
                return None
            
            if pdu_response['varbinds']:
                vb = pdu_response['varbinds'][0]
                oid_tuple = tuple(vb.oid)
                return {oid_tuple: vb.value}
            
            return None
            
        except socket.timeout:
            console.print(f"[red]Timeout de la {agent_addr[0]}[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Eroare send_get_next_request: {e}[/red]")
            return None

    def send_set_request(self, agent_addr, oid, value, value_type):
        """
        Trimite SetRequest catre agent.
        
        Args:
            agent_addr: Tuplu (ip, port) al agentului
            oid: OID de modificat (lista de intregi)
            value: Valoarea noua
            value_type: Tipul BER (0x02 pentru INTEGER, 0x04 pentru OCTET STRING)
        
        Returns:
            bool: True daca succes, False altfel
        """
        try:
            varbind = VarBind(oid, value, value_type)
            request_id = self.get_next_request_id()
            pdu_data = encode_pdu_set_request(request_id, [varbind])
            message = encode_snmp_message(self.community, pdu_data)

            self.sock.sendto(message, agent_addr)
            response_data, addr = self.sock.recvfrom(4096)

            response = decode_snmp_message(response_data)
            pdu_response = response['pdu']

            if pdu_response['error_status'] != ERROR_NO_ERROR:
                console.print(f"[red]SetRequest esuat: error_status={pdu_response['error_status']}[/red]")
                return False

            console.print(f"[green]SetRequest reusit[/green]")
            return True

        except Exception as e:
            console.print(f"[red]Eroare send_set_request: {e}[/red]")
            return False

    def get_all_values(self):
        """
        Citeste toate valorile de la toti agentii.
        Actualizeaza self.current_values.
        """
        if not self.agents:
            console.print("[yellow]Nu exista agenti adaugati![/yellow]")
            return

        oids = [OID_CPU, OID_MEMORY, OID_DISK, OID_TEMP_VALUE,
                OID_TEMP_UNIT, OID_PROC_COUNT]

        for agent_addr in self.agents:
            values = self.send_get_request(agent_addr, oids)
            if values:
                self.current_values[agent_addr] = values

    def start_trap_listener(self):
        """Porneste thread-ul de ascultare trap-uri."""
        if self.trap_thread and self.trap_thread.is_alive():
            console.print("[yellow]Trap listener deja pornit[/yellow]")
            return

        self.running = True
        self.trap_sock.settimeout(1.0)
        self.trap_thread = threading.Thread(target=self._trap_listener_loop, daemon=True)
        self.trap_thread.start()
        console.print("[green]Trap listener pornit pe port[/green]", MANAGER_TRAP_PORT)

    def _trap_listener_loop(self):
        """Loop pentru ascultare trap-uri."""
        while self.running:
            try:
                data, addr = self.trap_sock.recvfrom(4096)

                if data:
                    snmp_msg = decode_snmp_message(data)
                    pdu_trap = snmp_msg['pdu']

                    trap_entry = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'agent_addr': pdu_trap['agent_addr'],
                        'generic_trap': pdu_trap['generic_trap'],
                        'specific_trap': pdu_trap['specific_trap'],
                        'enterprise': pdu_trap['enterprise'],
                        'time_stamp': pdu_trap['timestamp'],
                        'varbinds': pdu_trap['varbinds']
                    }

                    self.trap_log.append(trap_entry)
                    self._display_trap(trap_entry)

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    console.print(f"[red]Eroare trap listener: {e}[/red]")

    def _display_trap(self, trap_entry):
        """
        Afiseaza un trap frumos cu Rich.
        
        Args:
            trap_entry: Dictionar cu detaliile trap-ului
        """
        # Mapare trap types
        generic_names = {
            0: "coldStart", 1: "warmStart", 2: "linkDown",
            3: "linkUp", 4: "authFailure", 5: "egpNeighborLoss",
            6: "enterpriseSpecific"
        }

        specific_names = {
            1: "cpuOverThreshold",
            2: "memoryOverThreshold",
            3: "temperatureOverThreshold"
        }

        generic = trap_entry['generic_trap']
        generic_name = generic_names.get(generic, f"unknown({generic})")

        content = f"[yellow]TRAP NOTIFICATION[/yellow]\n\n"
        content += f"[cyan]Timestamp:[/cyan]     {trap_entry['timestamp']}\n"
        content += f"[cyan]Agent:[/cyan]         {trap_entry['agent_addr']}\n"
        content += f"[cyan]Generic Trap:[/cyan]  {generic_name} ({generic})\n"

        if generic == 6:
            specific = trap_entry['specific_trap']
            specific_name = specific_names.get(specific, f"custom({specific})")
            content += f"[cyan]Specific Trap:[/cyan] {specific_name} ({specific})\n"

        if trap_entry['varbinds']:
            content += f"\n[cyan]Variables:[/cyan]\n"
            for vb in trap_entry['varbinds']:
                oid_str = '.'.join(map(str, vb.oid))
                content += f"  - OID: {oid_str} = {vb.value}\n"

        panel = Panel(content, border_style="red", title="[bold red]TRAP[/bold red]")
        console.print(panel)

    def stop_trap_listener(self):
        """Opreste trap listener."""
        if self.trap_thread and self.trap_thread.is_alive():
            self.running = False
            self.trap_thread.join(timeout=2)
            console.print("[green]Trap listener oprit[/green]")

    def start_auto_refresh(self, interval):
        """
        Porneste auto-refresh periodic.
        
        Args:
            interval: Interval in secunde intre refresh-uri
        """
        if self.refresh_thread and self.refresh_thread.is_alive():
            console.print("[yellow]Auto-refresh deja pornit[/yellow]")
            return

        self.refresh_interval = interval
        self.running = True
        self.refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self.refresh_thread.start()
        console.print(f"[green]Auto-refresh pornit (interval={interval}s)[/green]")

    def _refresh_loop(self):
        """Loop auto-refresh."""
        while self.running and self.refresh_interval > 0:
            time.sleep(self.refresh_interval)
            if self.running:
                console.rule(f"[bold cyan]AUTO-REFRESH {datetime.now().strftime('%H:%M:%S')}[/bold cyan]")
                self.get_all_values()
                self.display_current_values()

    def stop_auto_refresh(self):
        """Opreste auto-refresh."""
        if self.refresh_thread and self.refresh_thread.is_alive():
            self.refresh_interval = 0
            self.running = False
            self.refresh_thread.join(timeout=2)
            console.print("[green]Auto-refresh oprit[/green]")

    def display_current_values(self):
        """Afiseaza valorile curente intr-un tabel Rich."""
        if not self.current_values:
            console.print("[yellow]Nu exista valori de afisat[/yellow]")
            return

        # Cream tabel frumos
        table = Table(title="[bold cyan]Valori Curente MIB[/bold cyan]",
                     box=box.ROUNDED,
                     show_header=True,
                     header_style="bold magenta")

        table.add_column("Resource", style="cyan", no_wrap=True)
        table.add_column("Value", style="green", justify="right")
        table.add_column("Unit", style="yellow")
        table.add_column("Agent", style="blue")

        for agent_addr, values in self.current_values.items():
            agent_ip = agent_addr[0]

            for oid_tuple, value in values.items():
                oid_name = OID_NAMES.get(oid_tuple, '.'.join(map(str, oid_tuple)))

                # Formatare speciala pentru unit temperatura
                if oid_tuple == tuple(OID_TEMP_UNIT):
                    value_str = str(value)
                    unit = TEMP_UNITS.get(value, "")
                elif oid_tuple == tuple(OID_CPU):
                    value_str = str(value)
                    unit = "%"
                elif oid_tuple == tuple(OID_MEMORY):
                    value_str = str(value)
                    unit = "MiB"
                elif oid_tuple == tuple(OID_DISK):
                    value_str = str(value)
                    unit = "MiB"
                elif oid_tuple == tuple(OID_TEMP_VALUE):
                    value_str = str(value)
                    # Extrage unitatea curenta
                    temp_unit_val = values.get(tuple(OID_TEMP_UNIT), 0)
                    unit = TEMP_UNITS.get(temp_unit_val, "°C")
                elif oid_tuple == tuple(OID_PROC_COUNT):
                    value_str = str(value)
                    unit = "procese"
                else:
                    value_str = str(value)
                    unit = ""

                table.add_row(oid_name, value_str, unit, agent_ip)

        console.print(table)

    def display_trap_log(self):
        """Afiseaza log-ul trap-urilor."""
        if not self.trap_log:
            console.print("[yellow]Niciun trap primit[/yellow]")
            return

        table = Table(title="[bold red]Trap Log[/bold red]",
                     box=box.ROUNDED,
                     show_header=True,
                     header_style="bold red")

        table.add_column("#", style="dim", width=4)
        table.add_column("Timestamp", style="cyan")
        table.add_column("Agent", style="blue")
        table.add_column("Type", style="yellow")
        table.add_column("OID", style="green")
        table.add_column("Value", style="magenta")

        for idx, trap in enumerate(self.trap_log, 1):
            generic = trap['generic_trap']
            specific = trap['specific_trap']

            if generic == 6:
                trap_type = f"Enterprise #{specific}"
            else:
                trap_type = f"Generic #{generic}"

            # Extrage info din varbinds
            oid_str = ""
            value_str = ""
            if trap['varbinds']:
                vb = trap['varbinds'][0]
                oid_str = '.'.join(map(str, vb.oid))
                value_str = str(vb.value)

            table.add_row(
                str(idx),
                trap['timestamp'],
                trap['agent_addr'],
                trap_type,
                oid_str,
                value_str
            )

        console.print(table)

    def export_csv(self, filename="snmp_data.csv"):
        """
        Exporta datele curente in CSV.
        
        Args:
            filename: Numele fisierului CSV (default: "snmp_data.csv")
        """
        if not self.current_values:
            console.print("[yellow]Nu exista date de exportat[/yellow]")
            return

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Agent', 'Resource', 'Value', 'Unit'])

                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                for agent_addr, values in self.current_values.items():
                    agent_ip = agent_addr[0]

                    for oid_tuple, value in values.items():
                        oid_name = OID_NAMES.get(oid_tuple, '.'.join(map(str, oid_tuple)))

                        # Determina unitatea
                        if oid_tuple == tuple(OID_CPU):
                            unit = "%"
                        elif oid_tuple == tuple(OID_MEMORY):
                            unit = "MiB"
                        elif oid_tuple == tuple(OID_DISK):
                            unit = "MiB"
                        elif oid_tuple == tuple(OID_TEMP_VALUE):
                            temp_unit_val = values.get(tuple(OID_TEMP_UNIT), 0)
                            unit = TEMP_UNITS.get(temp_unit_val, "°C")
                        elif oid_tuple == tuple(OID_PROC_COUNT):
                            unit = "procese"
                        else:
                            unit = ""

                        writer.writerow([timestamp, agent_ip, oid_name, value, unit])

            console.print(f"[green]Date exportate in {filename}[/green]")

        except Exception as e:
            console.print(f"[red]Eroare export CSV: {e}[/red]")

    def close(self):
        """Inchide socket-urile si opreste thread-urile."""
        self.stop_trap_listener()
        self.stop_auto_refresh()
        self.sock.close()
        self.trap_sock.close()