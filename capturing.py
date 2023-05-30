from scapy.all import *
import psutil
from collections import defaultdict
import os
from threading import Thread
import pandas as pd
import subprocess

all_macs = {iface.mac for iface in ifaces.values()}
connection2pid = {}

pid2traffic = defaultdict(lambda: [0, 0])

global_df = None
warning_terminal = None
is_program_running = True

speed_limit = 1024

warning_message = "Process is exceeding the bandwidth limit!"
standard_message = "OK"

def get_size(bytes):
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024

def process_packet(packet):
    global pid2traffic
    try:
        packet_connection = (packet.sport, packet.dport)
    except(AttributeError, IndexError):
        pass
    else:
        packet_pid = connection2pid.get(packet_connection)
        if packet_pid:
            if packet.src in all_macs:
                pid2traffic[packet_pid][0] += len(packet)
            else:
                pid2traffic[packet_pid][1] += len(packet)

def get_connections():
    print("a")
    global connection2pid
    while is_program_running:
        for c in psutil.net_connections():
            if c.laddr and c.raddr and c.pid:
                connection2pid[(c.laddr.port, c.raddr.port)] = c.pid
                connection2pid[(c.raddr.port, c.laddr.port)] = c.pid
        time.sleep(1)

def print_pid2traffic():
    global global_df
    processes = []

    for pid, traffic in pid2traffic.items():
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            continue
        name = str(p.name).split(",")[1].split("'")[1]

        try:
            create_time = datetime.fromtimestamp(p.create_time())
        except OSError:
            create_time = datetime.fromtimestamp(psutil.boot_time())
        
        process = {"pid": pid, "name": name, "create_time": create_time, "Upload": traffic[0], "Download": traffic[1]}

        try:
            process["Upload Speed"] = traffic[0] - global_df.at[pid, "Upload"]
            process["Download Speed"] = traffic[1] - global_df.at[pid, "Download"]
            if process["Download Speed"] > speed_limit:
                process["Message"] = warning_message
            else:
                process["Message"] = standard_message
                send_warning_command(pid)
        except (KeyError, AttributeError):
            process["Upload Speed"] = traffic[0]
            process["Download Speed"] = traffic[1]

        processes.append(process)
    
    df = pd.DataFrame(processes)
    try:
        df = df.set_index("pid")
        df.sort_values("Download", inplace=True, ascending=False)
    except KeyError as e:
        pass

    printing_df = df.copy()
    try:
        printing_df["Download"] = printing_df["Download"].apply(get_size)
        printing_df["Upload"] = printing_df["Upload"].apply(get_size)
        printing_df["Download Speed"] = printing_df["Download Speed"].apply(get_size).apply(lambda s: f"{s}/s")
        printing_df["Upload Speed"] = printing_df["Upload Speed"].apply(get_size).apply(lambda s: f"{s}/s")
    except KeyError as e:
        pass

    os.system("cls") if "nt" in os.name else os.system("clear")

    print(printing_df.to_string())

    global_df = df

def print_stats():
    while is_program_running:
        time.sleep(1)
        print_pid2traffic()

def kill_process(pid):
    print("oeoeoe")
    os.system(f"taskkill /F /PID {pid}")

def show_warning(pid):
    subprocess.call(f"echo WARNING: Process {pid} is exceeding the bandwidth limit!", shell=True)

def send_warning_command(pid):
    # Tu código para enviar el comando "echo" a la terminal de advertencias
    #global warning_terminal
    global warning_terminal
    command = f'echo El proceso {pid} está excediendo el límite de velocidad!'
    command_bytes = command.encode('utf-8')
    warning_terminal.stdin.write(command_bytes + b'\n')
    warning_terminal.stdin.flush()

if __name__ == "__main__":
    warning_terminal = subprocess.Popen('start cmd', stdin=subprocess.PIPE, shell=True)
    time.sleep(2)  # Esperar a que la nueva terminal se abra

    printing_thread = Thread(target=print_stats)
    printing_thread.start()

    connections_thread = Thread(target=get_connections)
    connections_thread.start()

print("Started sniffing")

sniff(prn=process_packet, store=False)

is_program_running = False