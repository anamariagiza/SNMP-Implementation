"""
Interfata CLI pentru SNMP Manager folosind Python Rich.

Acest modul contine interfata utilizator (UI) pentru managerul SNMP,
separata de logica business pentru o mai buna modularitate.

Referinte:
[1] Python Rich documentation
    https://rich.readthedocs.io/
"""

import sys
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.table import Table

# Import manager SNMP
from manager import (
    SNMPManager,
    AGENT_PORT,
    OID_CPU, OID_MEMORY, OID_DISK, OID_TEMP_VALUE,
    OID_TEMP_UNIT, OID_PROC_COUNT,
    OID_CPU_MAX, OID_MEM_MAX, OID_TEMP_MAX,
    OID_NAMES, TEMP_UNITS
)

# Console global pentru Rich
console = Console()


class ManagerUI:
    """
    Interfata CLI pentru SNMP Manager.
    
    Responsabilitati:
    - Afisare meniuri si headere
    - Interactiune cu utilizatorul
    - Delegare comenzi catre SNMPManager
    """
    
    def __init__(self):
        """Initializeaza UI si managerul SNMP."""
        self.manager = SNMPManager()
    
    def print_header(self):
        """Afiseaza header-ul aplicatiei."""
        console.clear()
        
        header_text = """
                  SNMP Manager v1.0 - Interfata CLI cu Python Rich                         
        """
        
        console.print(header_text, style="bold cyan")
    
    def print_menu(self):
        """Afiseaza meniul principal."""
        menu_table = Table(show_header=False, box=box.ROUNDED,
                          border_style="cyan", padding=(0, 2))
        
        menu_table.add_column("Option", style="bold yellow", width=4)
        menu_table.add_column("Description", style="white")
        
        menu_table.add_row("1", "Adauga agent")
        menu_table.add_row("2", "Sterge agent")
        menu_table.add_row("3", "Lista agenti")
        menu_table.add_row("4", "Get values (refresh manual)")
        menu_table.add_row("5", "Walk MIB (GetNext)")
        menu_table.add_row("6", "Set temperature unit (C/F/K)")
        menu_table.add_row("7", "Set CPU threshold")
        menu_table.add_row("8", "Set Memory threshold")
        menu_table.add_row("9", "Set Temperature threshold")
        menu_table.add_row("10", "Start auto-refresh")
        menu_table.add_row("11", "Stop auto-refresh")
        menu_table.add_row("12", "View trap log")
        menu_table.add_row("13", "Export CSV")
        menu_table.add_row("0", "[bold red]Exit[/bold red]")
        
        panel = Panel(menu_table, title="[bold cyan]Meniu Principal[/bold cyan]",
                     border_style="cyan")
        console.print(panel)
    
    def handle_add_agent(self):
        """Gestioneaza adaugarea unui agent."""
        ip = Prompt.ask("[cyan]IP agent[/cyan]", default="127.0.0.1")
        port_str = Prompt.ask("[cyan]Port[/cyan]", default=str(AGENT_PORT))
        try:
            port = int(port_str)
            self.manager.add_agent(ip, port)
        except ValueError:
            console.print("[red]Port invalid![/red]")
    
    def handle_remove_agent(self):
        """Gestioneaza stergerea unui agent."""
        if not self.manager.agents:
            console.print("[yellow]Nu exista agenti![/yellow]")
            return
        
        console.print("\n[cyan]Agenti disponibili:[/cyan]")
        for idx, (ip, port) in enumerate(self.manager.agents, 1):
            console.print(f"  {idx}. {ip}:{port}")
        
        idx_str = Prompt.ask("[cyan]Index agent de sters[/cyan]")
        try:
            idx = int(idx_str) - 1
            if 0 <= idx < len(self.manager.agents):
                ip, port = self.manager.agents[idx]
                self.manager.remove_agent(ip, port)
            else:
                console.print("[red]Index invalid![/red]")
        except ValueError:
            console.print("[red]Input invalid![/red]")
    
    def handle_list_agents(self):
        """Gestioneaza afisarea listei de agenti."""
        if not self.manager.agents:
            console.print("[yellow]Nu exista agenti adaugati![/yellow]")
        else:
            table = Table(title="[bold cyan]Agenti Configurati[/bold cyan]",
                        box=box.ROUNDED)
            table.add_column("#", style="dim", width=4)
            table.add_column("IP", style="cyan")
            table.add_column("Port", style="yellow")
            
            for idx, (ip, port) in enumerate(self.manager.agents, 1):
                table.add_row(str(idx), ip, str(port))
            
            console.print(table)
    
    def handle_get_values(self):
        """Gestioneaza citirea valorilor de la agenti."""
        console.print("\n[cyan]Citire valori...[/cyan]")
        self.manager.get_all_values()
        self.manager.display_current_values()
    
    def handle_walk_mib(self):
        """Gestioneaza parcurgerea MIB-ului cu GetNext."""
        if not self.manager.agents:
            console.print("[yellow]Nu exista agenti![/yellow]")
            return
        
        console.print("\n[cyan]Selecteaza agent:[/cyan]")
        for idx, (ip, port) in enumerate(self.manager.agents, 1):
            console.print(f"  {idx}. {ip}:{port}")
        
        idx_str = Prompt.ask("[cyan]Index agent[/cyan]")
        try:
            idx = int(idx_str) - 1
            if 0 <= idx < len(self.manager.agents):
                agent_addr = self.manager.agents[idx]
                
                # Porneste de la primul OID
                start_oid = Prompt.ask("[cyan]OID start (ex: 1.3.6.1.4.1.99999.2)[/cyan]", 
                                      default="1.3.6.1.4.1.99999.2")
                
                current_oid = start_oid.split('.')
                current_oid = [int(x) for x in current_oid if x]
                
                console.print(f"\n[cyan]Parcurgere MIB pornind de la {start_oid}...[/cyan]\n")
                
                count = 0
                max_iterations = 10  # Limita pentru demo
                
                while count < max_iterations:
                    result = self.manager.send_get_next_request(agent_addr, current_oid)
                    
                    if not result:
                        break
                    
                    for oid_tuple, value in result.items():
                        oid_str = '.'.join(map(str, oid_tuple))
                        oid_name = OID_NAMES.get(oid_tuple, "Unknown")
                        console.print(f"[green]{oid_str}[/green] ({oid_name}) = [yellow]{value}[/yellow]")
                        current_oid = list(oid_tuple)
                    
                    count += 1
                
                console.print(f"\n[green]Parcurgere completa ({count} OID-uri)[/green]")
            else:
                console.print("[red]Index invalid![/red]")
        except ValueError:
            console.print("[red]Input invalid![/red]")
    
    def handle_set_temp_unit(self):
        """Gestioneaza setarea unitatii de temperatura."""
        console.print("\n[cyan]Selecteaza unitate temperatura:[/cyan]")
        console.print("  0 = Celsius (°C)")
        console.print("  1 = Fahrenheit (°F)")
        console.print("  2 = Kelvin (K)")
        
        unit = Prompt.ask("[cyan]Unitate[/cyan]", choices=['0', '1', '2'])
        
        for agent_addr in self.manager.agents:
            self.manager.send_set_request(agent_addr, OID_TEMP_UNIT, int(unit), 0x02)
    
    def handle_set_cpu_threshold(self):
        """Gestioneaza setarea pragului CPU."""
        threshold = IntPrompt.ask("[cyan]CPU Max (%)[/cyan]", default=85)
        for agent_addr in self.manager.agents:
            self.manager.send_set_request(agent_addr, OID_CPU_MAX, threshold, 0x02)
    
    def handle_set_memory_threshold(self):
        """Gestioneaza setarea pragului memoriei."""
        threshold = IntPrompt.ask("[cyan]Memory Max (MiB)[/cyan]", default=4096)
        for agent_addr in self.manager.agents:
            self.manager.send_set_request(agent_addr, OID_MEM_MAX, threshold, 0x02)
    
    def handle_set_temp_threshold(self):
        """Gestioneaza setarea pragului temperaturii."""
        threshold = IntPrompt.ask("[cyan]Temperature Max[/cyan]", default=70)
        for agent_addr in self.manager.agents:
            self.manager.send_set_request(agent_addr, OID_TEMP_MAX, threshold, 0x02)
    
    def handle_start_auto_refresh(self):
        """Gestioneaza pornirea auto-refresh."""
        interval = IntPrompt.ask("[cyan]Interval (secunde)[/cyan]", default=5)
        self.manager.start_auto_refresh(interval)
    
    def handle_stop_auto_refresh(self):
        """Gestioneaza oprirea auto-refresh."""
        self.manager.stop_auto_refresh()
    
    def handle_view_trap_log(self):
        """Gestioneaza afisarea log-ului de trap-uri."""
        self.manager.display_trap_log()
    
    def handle_export_csv(self):
        """Gestioneaza exportul in CSV."""
        filename = Prompt.ask("[cyan]Nume fisier[/cyan]", default="snmp_data.csv")
        self.manager.export_csv(filename)
    
    def handle_exit(self):
        """Gestioneaza iesirea din aplicatie."""
        console.print("\n[yellow]Oprire manager...[/yellow]")
        self.manager.close()
        console.print("[green]La revedere![/green]\n")
    
    def run(self):
        """Loop principal al interfetei."""
        self.print_header()
        
        # Pornim trap listener automat
        self.manager.start_trap_listener()
        
        # Mapare optiuni -> functii handler
        handlers = {
            '1': self.handle_add_agent,
            '2': self.handle_remove_agent,
            '3': self.handle_list_agents,
            '4': self.handle_get_values,
            '5': self.handle_walk_mib,
            '6': self.handle_set_temp_unit,
            '7': self.handle_set_cpu_threshold,
            '8': self.handle_set_memory_threshold,
            '9': self.handle_set_temp_threshold,
            '10': self.handle_start_auto_refresh,
            '11': self.handle_stop_auto_refresh,
            '12': self.handle_view_trap_log,
            '13': self.handle_export_csv,
            '0': self.handle_exit,
        }
        
        # Loop meniu
        while True:
            self.print_menu()
            
            choice = Prompt.ask("\n[bold yellow]Selecteaza optiune[/bold yellow]",
                               default="0")
            
            if choice == '0':
                self.handle_exit()
                break
            elif choice in handlers:
                handlers[choice]()
            else:
                console.print("[red]Optiune invalida![/red]")
            
            # Pauza inainte de a afisa din nou meniul
            console.print("\n[dim]Apasa Enter pentru a continua...[/dim]")
            input()


def main():
    """Functia principala - entry point."""
    ui = ManagerUI()
    ui.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Intrerupere primita. Oprire...[/yellow]")
        sys.exit(0)