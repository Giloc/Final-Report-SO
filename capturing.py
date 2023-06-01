from scapy.all import *
import psutil
from collections import defaultdict
from threading import Thread
import pandas as pd
import tkinter

all_macs = {iface.mac for iface in ifaces.values()}
connection2pid = {}

pid2traffic = defaultdict(lambda: [0, 0])

global_df = pd.DataFrame()

is_program_running = True

speed_limit = 1024

warning_message = "Process is exceeding the bandwidth limit!"
standard_message = "OK"

warning_processes = {}

def get_size(bytes):
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024

def process_packet(packet):
    if not is_program_running:
        sys.exit()
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
    global connection2pid
    while is_program_running:
        for c in psutil.net_connections():
            if c.laddr and c.raddr and c.pid:
                connection2pid[(c.laddr.port, c.raddr.port)] = c.pid
                connection2pid[(c.raddr.port, c.laddr.port)] = c.pid
        time.sleep(1)

def get_pid2traffic():
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
                warning_processes[pid] = name
                process["Message"] = warning_message
            else:
                process["Message"] = standard_message
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

    global_df = df

def print_stats():
    while is_program_running:
        time.sleep(1)
        get_pid2traffic()    

def update_data():
    if not global_df.empty:
        printing_df = global_df.copy()
        try:
            printing_df["Download"] = printing_df["Download"].apply(get_size)
            printing_df["Upload"] = printing_df["Upload"].apply(get_size)
            printing_df["Download Speed"] = printing_df["Download Speed"].apply(get_size).apply(lambda s: f"{s}/s")
            printing_df["Upload Speed"] = printing_df["Upload Speed"].apply(get_size).apply(lambda s: f"{s}/s")
        except KeyError as e:
            pass
        updated_data = printing_df.to_string()
        data_listbox.delete("1.0", "end")
        data_listbox.insert(tkinter.INSERT, updated_data)
        warning.delete(0, "end")
        for pid in warning_processes.keys():
            warning.insert("end", get_message(pid))
        warning_processes.clear()
    
    window.after(1000, update_data)

def get_message(pid):
    return f"Process {pid} ({warning_processes[pid]}) is exceeding the bandwidth limit!"

def on_window_close():
    global is_program_running, sniffer
    is_program_running = False
    window.destroy()
    sys.exit()

if __name__ == "__main__":
    printing_thread = Thread(target=print_stats)
    printing_thread.start()

    connections_thread = Thread(target=get_connections)
    connections_thread.start()

    window = tkinter.Tk()
    window.title("Netwrok usage by process")
    window.geometry("1280x720")
    title_label = tkinter.Label(window, text="Netwrok usage by process")
    title_label.pack()
    scrollbar = tkinter.Scrollbar(window)
    scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
    data_listbox = tkinter.Text(window, yscrollcommand=scrollbar.set, height=20, width=220)
    data_listbox.pack()
    
    warning = tkinter.Listbox(window, height=10, width=220)
    warning.pack()
    scrollbar.config(command=data_listbox.yview)
    update_data()

    sniffing_thread = Thread(target=lambda: sniff(prn=process_packet, store=False))
    sniffing_thread.start()

    window.protocol("WM_DELETE_WINDOW", on_window_close)

    window.mainloop()
    is_program_running = False
