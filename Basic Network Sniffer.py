#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   🕵️‍♂️  CodeAlpha Network Sniffer - By Shounak Gan (2025)         ║
║   A fun, colorful, and educational packet sniffer!                 ║
║   Version: 1.1 | Author: Shounak Gan                               ║
╚══════════════════════════════════════════════════════════════════════╝
"""

__author__ = "Shounak Gan"
__version__ = "1.1"
import signal
import socket
import struct
import textwrap
import sys
import argparse
from datetime import datetime
import os

# ANSI color codes for pretty output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    print(f"""{Colors.HEADER}
╔══════════════════════════════════════════════════════════════════════╗
║   🕵️‍♂️  CodeAlpha Network Sniffer - By Shounak Gan (2025)         ║
║   A fun, colorful, and educational packet sniffer!                 ║
║   Version: {__version__} | Author: Shounak Gan                     ║
╚══════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}""")

def list_interfaces():
    """List available interfaces (Linux only)"""
    ifaces = []
    try:
        for iface in os.listdir('/sys/class/net/'):
            ifaces.append(iface)
    except Exception:
        pass
    return ifaces

def mac_addr(bytes_addr):
    return ':'.join('%02x' % b for b in bytes_addr)

def ipv4(addr):
    return '.'.join(map(str, addr))

def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return mac_addr(dest_mac), mac_addr(src_mac), socket.htons(proto), data[14:]

def parse_ip_header(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    proto = data[9]
    src = ipv4(data[12:16])
    target = ipv4(data[16:20])
    return proto, src, target, data[header_length:]

def protocol_name(proto_num):
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, f"Other({proto_num})")

def hexdump(src, length=16):
    """Return a hexdump string for the given bytes."""
    result = []
    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = ' '.join([f"{b:02x}" for b in s])
        text = ''.join([chr(b) if 32 <= b < 127 else '.' for b in s])
        result.append(f"{i:04x}  {hexa:<{length*3}}  {text}")
    return '\n'.join(result)

def is_admin():
    """Check if running as admin/root."""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except Exception:
        return False

class PacketSniffer:
    def __init__(self, interface=None, count=None, protocol_filter=None, log_file=None):
        self.interface = interface
        self.count = count
        self.protocol_filter = protocol_filter.lower() if protocol_filter else None
        self.log_file = log_file
        self.running = True
        self.packet_counter = 0
        self.csv_writer = None
        self.csv_file = None

    def start_capture(self):
        if not is_admin():
            print(f"{Colors.FAIL}ERROR: Please run as administrator/root!{Colors.ENDC}")
            sys.exit(1)

        try:
            if sys.platform.startswith('win'):
                conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                conn.bind((socket.gethostbyname(socket.gethostname()), 0))
                conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                if self.interface:
                    conn.bind((self.interface, 0))
        except PermissionError:
            print(f"{Colors.FAIL}ERROR: Permission denied. Try running as root/administrator.{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}Socket error: {e}{Colors.ENDC}")
            sys.exit(1)

        if self.log_file:
            self.csv_file = open(self.log_file, 'w', newline='', encoding='utf-8')
            self.csv_writer = csv.writer(self.csv_file)
            self.csv_writer.writerow(['Timestamp', 'Protocol', 'Src MAC', 'Dst MAC', 'Src IP', 'Dst IP', 'Length'])

        print(f"{Colors.OKGREEN}Started packet capture. Press Ctrl+C to stop.{Colors.ENDC}\n")
        signal.signal(signal.SIGINT, self.stop_capture)

        try:
            while self.running:
                raw_data, addr = conn.recvfrom(65535)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if sys.platform.startswith('win'):
                    proto, src_ip, dst_ip, payload = parse_ip_header(raw_data)
                    src_mac = dst_mac = "N/A"
                else:
                    dst_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)
                    if eth_proto == 8:  # IPv4
                        proto, src_ip, dst_ip, payload = parse_ip_header(data)
                    else:
                        continue  # Not IPv4
                proto_str = protocol_name(proto)
                if self.protocol_filter and proto_str.lower() != self.protocol_filter:
                    continue

                self.packet_counter += 1
                print(f"{Colors.OKBLUE}[{self.packet_counter}] {timestamp} | {Colors.BOLD}{proto_str}{Colors.ENDC} | "
                      f"{Colors.OKCYAN}{src_mac} ({src_ip}){Colors.ENDC} → {Colors.OKCYAN}{dst_mac} ({dst_ip}){Colors.ENDC} | "
                      f"Length: {len(raw_data)} bytes")

                # Show a short hexdump and payload preview
                preview = payload[:32]
                ascii_preview = ''.join([chr(b) if 32 <= b < 127 else '.' for b in preview])
                print(f"{Colors.WARNING}Payload preview:{Colors.ENDC} {ascii_preview}")
                print(f"{Colors.HEADER}Hexdump:\n{hexdump(preview, 16)}{Colors.ENDC}")

                if self.csv_writer:
                    self.csv_writer.writerow([timestamp, proto_str, src_mac, dst_mac, src_ip, dst_ip, len(raw_data)])

                if self.count and self.packet_counter >= self.count:
                    break
        except KeyboardInterrupt:
            self.stop_capture()
        finally:
            if self.csv_file:
                self.csv_file.close()
            if sys.platform.startswith('win'):
                try:
                    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            print(f"\n{Colors.WARNING}Capture stopped. {self.packet_counter} packets captured.{Colors.ENDC}")

    def stop_capture(self, signum=None, frame=None):
        self.running = False

def main():
    parser = argparse.ArgumentParser(
        description='CodeAlpha Network Packet Sniffer by Shounak Gan'
    )
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-p', '--protocol', choices=['tcp', 'udp', 'icmp'], help='Filter by protocol')
    parser.add_argument('-i', '--interface', help='Network interface (Linux only)')
    parser.add_argument('-l', '--log', help='Log captured packets to CSV file')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__} by Shounak Gan')
    args = parser.parse_args()

    print_banner()
    print(f"{Colors.WARNING}WARNING: This tool is for educational purposes only.")
    print("Ensure you have permission to monitor network traffic.")
    print("Use responsibly and in accordance with local laws.{Colors.ENDC}\n")

    if not args.interface and not sys.platform.startswith('win'):
        print(f"{Colors.OKCYAN}Available interfaces:{Colors.ENDC} {', '.join(list_interfaces())}")
        print(f"{Colors.WARNING}Tip: Use -i <interface> to specify one!{Colors.ENDC}\n")

    sniffer = PacketSniffer(
        interface=args.interface,
        count=args.count,
        protocol_filter=args.protocol,
        log_file=args.log
    )
    sniffer.start_capture()

if __name__ == "__main__":
    main()
