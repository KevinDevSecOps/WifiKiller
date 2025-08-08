from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon

def scan_wifi(interface="wlan0"):
    print("[+] Escaneando redes WiFi...")
    networks = []
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode()
            bssid = pkt[Dot11].addr2
            networks.append((ssid, bssid))
            print(f"Red: {ssid} | BSSID: {bssid}")
    sniff(iface=interface, prn=packet_handler, timeout=10)
    return networks

if __name__ == "__main__":
    scan_wifi()
