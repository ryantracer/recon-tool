from scapy.all import ARP, Ether, srp, sr1, IP, TCP
import socket
import argparse 

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--internet_protocol', help='ip for scanning', required=False)
parser.add_argument('-r', '--recon', 
                    help='provide this argument if you wish to test the available hosts in the network, you should give the ip range of the network in CIDR notation (i.e 192.168.0.0/24)', 
                    required=False)
parser.add_argument('-w', '--write', help='write the results in a txt file [help: -w results.txt]', required=False)
parser.add_argument('-s', '--sniff', help='sniff packets from a specific interface (i.e.: eth0, en0, wlo1...)', required=False)

args = parser.parse_args()


def device_scanner(ip):
    try:
        print(f'[=] Scanning ports on {ip} [=]')
        
        t_ip = socket.gethostbyname(ip)
        f = None 
        
        if args.write:
            f = open(args.write, 'w', encoding='utf-8')
            f.write('List of open ports:')
        
        open_ports = 0 
        
        for i in range(1, 1025):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            c = s.connect_ex((t_ip, i))
            if c == 0:
                open_ports += 1
                print(f'[+]{i} OPEN[+]')
                if args.write:
                    f.write(f'\n{i}')
            else:
                pass
            s.close()
        print(f'{open_ports} open ports')
        if args.write:
            f.write(f'\n{open_ports} open ports\n')

        packet = IP(dst=ip) / TCP(dport=80, flags='S')

        print('[/] Receiving packets for gathering information [/]')
        response = sr1(packet, verbose=0, timeout=2)
        print(f'[+] Received: {response}')
        if response.haslayer(IP):
            print(f'TTL: {response[IP].ttl}')
            if args.write:
                f.write(f'TTL: {response[IP].ttl}')
        if response.haslayer(TCP):
            print(f'TCP layer window: {response[TCP].window}')
            if args.write:
                f.write(f'TCP layer window: {response[TCP].window}')

        if f:
            f.write('\n')
            f.close()

    except KeyboardInterrupt:
        print('\n[!] Process interrupted by user [!]')
    except socket.gaierror:
        print('\n[!] Could not be resolved [!]')
    except socket.error as e:
        print(f'\n[!] Error: {e} [!]')

def recon(ip_range):
    try:
        f = None
        if args.write:
            f = open(args.write, 'w', encoding='utf-8')
            f.write('List of detected hosts:')
        print('='*60)
        print(f'[=] Sending ARP requests [=]')
        print('[=] Listing all devices that answered [=]\n')
        arp_request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_range)
        ans, unansw = srp(arp_request, timeout=2, verbose=0)
        
        if ans:
            for sent, received in ans:
                print(f'[+] IP: {received.psrc} MAC: {received.hwsrc} [+]')
                if args.write:
                    f.write(f'\n{received.psrc} | {received.hwsrc}')
        print('='*60)
        if f:
            f.write('\n')
            f.close()
    except Exception as e:
        print(f'[!] error [!]\n\n {e}')

def sniffer(iface):
    print('[>] Press CTRL-C to stop listening')
    f = None
    if args.write:
        f = open(args.write, 'w', encoding='utf-8')
        f.write(f'[/] Listening on {iface} [/]')
    
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.bind((iface, 0))

    try:
        while True:
            raw_data, addr = s.recvfrom(65535)
            p = Ether(raw_data)
            print(p.summary())
            if f:
              f.write(f'\n{p.summary()}\n')
    except KeyboardInterrupt:
        print('\n[!] Shutdown [!]')
    finally:
        if f:
            f.close()

if __name__ == '__main__':
    if args.internet_protocol:
        device_scanner(args.internet_protocol)
    elif args.recon:
        recon(args.recon)
    elif args.sniff:
        sniffer(args.sniff)
    else:
        print('Usage: python recon-script.py -i <ip address> | -r <ip range> (optional: -w filename.txt for writing results in a .txt file)')
        print('Add: the recon method uses ARP requests for reconnaissance and some devices will not always answer, it is recommended to try it more than one time')
