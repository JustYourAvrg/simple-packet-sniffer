import psutil
import time

from tabulate import tabulate
from scapy.all import *
from rich.console import Console

console = Console()


# function to get all the network interfaces on the system
def get_all_network_interfaces():
    try:
        interfaces = psutil.net_if_addrs()
        return list(interfaces.keys())
    except AttributeError as e:
        print(f"Error: {e}")
        exit()
        
        
# Dictionary containing all the interface data
interface_data = {
    "Interface:": get_all_network_interfaces(),
    "IP Address:": [i[1].address for i in psutil.net_if_addrs().values()],
    "IPv6 Address:": [i[1].address for i in psutil.net_if_addrs().values() if i[1].address.startswith("fe80")],
    "MAC Address:": [i[0].address for i in psutil.net_if_addrs().values()],
    "Netmask:": [i[1].netmask for i in psutil.net_if_addrs().values()],
    "Broadcast IP:": [i[1].broadcast for i in psutil.net_if_addrs().values()], 
}

# print the interface data in a table
console.print(tabulate(interface_data, headers="keys", tablefmt="fancy_grid"))


# get the interface to sniff on
print() 
iface = console.input("[bold cyan]Choose an interface: [/bold cyan]")

# check if the interface is valid
if not iface in get_all_network_interfaces():
    console.print("[bold red]Invalid interface.[/bold red]")
    exit()

# ask the user if they want to save the sniffed packets to a file
save_to_file = console.input("[bold blue]Save to file? (y/n): [/bold blue]")
if save_to_file.lower() == "y":
    save = True
else:
    save = False


# function to sniff packets
def sniffer():
    while True:

        # while true, sniff packets
        try:
            
            sniffed_packets = sniff(iface=iface, count=1, filter="tcp or udp")
            
            for packet in sniffed_packets:
                src = packet[0][1].src
                dst = packet[0][1].dst
                sport = packet[0][1].sport
                proto = "TCP" if packet[0][1].proto == 6 else "UDP" if packet[0][1].proto == 17 else "Other"
                console.print(f"[bold blue]{src}[bold blue] [bold purple]|[bold purple] [bold green]{dst}[bold green] [bold purple]|[bold purple] [bold cyan]{sport}[bold cyan] [bold purple]|[bold purple] [bold red]{proto}[bold red]")
                
            time.sleep(0.5)
        
        # handle errors
        except AttributeError:
            pass
        except KeyboardInterrupt:
            console.print("[bold red]Exiting...[/bold red]")
            # save the sniffed packets to a file if the user chose to
            if save:
                wrpcap("sniffed.pcap", sniffed_packets)
                break
            elif not save:
                break
             

# print some info to the user
console.print("[bold red]Press CTRL+C to exit.[/bold red]")
console.print("[bold blue]Sniffing on interface: [/bold blue]" + iface)
print()
console.print("[bold red]-[/bold red]" * 50)
console.print("[bold blue]Source | Destination | Port | Protocol[/bold blue]")
# call the sniffer function
sniffer()








     


