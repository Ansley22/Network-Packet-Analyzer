import tkinter as tk
from tkinter import scrolledtext
import threading
from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time

packet_count = 0
sniffing = False

def get_protocol_name(protocol_num):
    if protocol_num == 1:
        return 'ICMP'
    elif protocol_num == 6:
        return 'TCP'
    elif protocol_num == 17:
        return 'UDP'
    else:
        return 'Other'

def packet_handler(packet):
    global packet_count
    packet_count += 1
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = get_protocol_name(ip_layer.proto)

        output_text = f"Packet #{packet_count}\n"
        output_text += f"Timestamp: {timestamp}\n"
        output_text += f"Source IP: {src_ip}\n"
        output_text += f"Destination IP: {dst_ip}\n"
        output_text += f"Protocol: {protocol}\n"

    
        if protocol == 'TCP':
            tcp_layer = packet[TCP]
            output_text += f"Source Port: {tcp_layer.sport}\n"
            output_text += f"Destination Port: {tcp_layer.dport}\n"
        elif protocol == 'UDP':
            udp_layer = packet[UDP]
            output_text += f"Source Port: {udp_layer.sport}\n"
            output_text += f"Destination Port: {udp_layer.dport}\n"
        elif protocol == 'ICMP':
            output_text += "ICMP Packet\n"
        
        if Raw in packet:
            output_text += f"Payload: {bytes(packet[Raw].load)}\n"

        output_text += "-" * 50 + "\n"

        
        text_area.insert(tk.END, output_text)
        text_area.see(tk.END)


def start_sniffing(filter_str=None, iface=None):
    global sniffing
    sniffing = True
    if filter_str:
        sniff(filter=filter_str, prn=packet_handler, iface=iface, stop_filter=lambda _: not sniffing)
    else:
        sniff(prn=packet_handler, iface=iface, stop_filter=lambda _: not sniffing)

def stop_sniffing():
    global sniffing
    sniffing = False


def start_sniffing_thread():
    iface = interface_entry.get()
    filter_str = filter_entry.get()
    sniff_thread = threading.Thread(target=start_sniffing, args=(filter_str, iface))
    sniff_thread.start()

def list_interfaces():
    interface_list = get_if_list()
    text_area.insert(tk.END, "Available Interfaces:\n")
    for iface in interface_list:
        text_area.insert(tk.END, f"- {iface}\n")
    text_area.insert(tk.END, "\n")
    print("Available Interfaces:", interface_list)

root = tk.Tk()
root.title("Network Packet Sniffer")


tk.Label(root, text="Network Interface (e.g., Ethernet, Wi-Fi):").grid(row=0, column=0, padx=10, pady=10)
interface_entry = tk.Entry(root)
interface_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Filter (e.g., tcp, udp):").grid(row=1, column=0, padx=10, pady=10)
filter_entry = tk.Entry(root)
filter_entry.grid(row=1, column=1, padx=10, pady=10)

text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=20)
text_area.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing_thread, bg="green", fg="white")
start_button.grid(row=3, column=0, padx=10, pady=10)

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white")
stop_button.grid(row=3, column=1, padx=10, pady=10)

list_button = tk.Button(root, text="List Interfaces", command=list_interfaces)
list_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()
