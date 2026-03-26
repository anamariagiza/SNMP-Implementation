import psutil


def cpu_load_procent():
    return int(psutil.cpu_percent(interval=0.1))

def mem_used_MiB():

    mem = psutil.virtual_memory() #se va intoarce un obiect cu mai multe atribute( .used este cel ce ne intereseaza)
    used_mib = int(mem.used / 1024 / 1024) #se realizeaza conversia din byte in megabyte
    return used_mib

def disk_used_MiB():

    disk = psutil.disk_usage('/') #     / - reprezinta radacina sistemului de fisiere( un fel de director ce contine toate directoarele)
    used_gb = int(disk.used / 1024 / 1024) #se realizeaza conversia din byte in megabyte
    return used_gb


def cpu_temp_c():
    try:
        temps = psutil.sensors_temperatures()
        for name, entries in temps.items():
            if 'coretemp' in name.lower():
                for entry in entries:
                    if entry.current is not None:
                        return int(entry.current)
        # Daca nu exista coretemp sau entry valid
        return 40
    except AttributeError:
        # pe Mac, psutil nu are sensors_temperatures
        return 40



def proc_counter():

    nr_procese = len(psutil.pids()) #se extrage numarul de procese active
    return int(nr_procese)


