import socket
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import logging
import argparse
import random
from datetime import datetime
from timeit import default_timer as timer

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#Pegar o banner da porta
def get_banner(port, protocol='tcp'):
    try:
        banner = socket.getservbyport(port, protocol)
        return banner
    except OSError:
        return "unknown"
#syn scan
def scan_port(ip, port, timeout=2, retries=3):
    sport=random.randint(1000, 65000)
        
    for _ in range(retries):
        pkt = IP(dst=ip)/TCP(sport=sport,dport=port, flags="S")
        response = sr1(pkt, timeout=timeout, verbose=0)

        if response is None:
            continue  # Tentar novamente

        if response.haslayer(TCP):
            if response[TCP].flags == "SA":
                banner = get_banner(port, "tcp")
                print(f"Port {port} is open - {banner[:40]}.")
                return "O"
            elif response[TCP].flags == "RA":
                print(f"Port {port} is closed.")
                return "C"

    print(f"Port {port} filtered.")
    return "F"

#fin scan
def finscan(ip, port,timeout=2):
    sport=random.randint(1000, 65000)
    
    pkt = IP(dst=ip)/TCP(sport=sport,dport=port, flags="F")
    response = sr1(pkt, timeout=timeout, verbose=0)

    if response is None:
         banner = get_banner(port,"tcp")
         print(f"Port {port} is open or filtered. - {banner[:40]}.")
         return "O"
    if response.haslayer(TCP):
        if response[TCP].flags == "RA":
            print(f"Port {port} is closed.")
            return "C"
    if response.haslayer(ICMP):
        if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            banner = get_banner(port,"tcp")
            print(f"Port {port} is filtered. - {banner[:40]}.")
            return "F"
            
#ack scan
def ackscan(ip, port, timeout=2, retries=3):
    sport = random.randint(1000, 65000)
    for _ in range(retries):
        pkt = IP(dst=ip)/TCP(sport=sport, dport=port, flags="A")
        response = sr1(pkt, timeout=timeout, verbose=False)

        # Verifica se response não é None antes de tentar acessar haslayer
        if response is not None:
            if response.haslayer(TCP):
                if response[TCP].flags == "R":
                    print(f"Port {port} is unfiltered.")
                    return "C"

            if response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                    banner = get_banner(port,"tcp")
                    print(f"Port {port} is filtered. - {banner[:40]}.")
                    return "F"
        else:
            banner = get_banner(port,"tcp")
            print(f"Port {port} is filtered. - {banner[:40]}.")
            return "F"
        
#extrair o intervalo de uma porta de uma string x-y        
def port_extraction(port):
    storeport = []
    # Verificando o valor da porta
    if port:
        # Verificando o intervalo das portas
        if "-" in port:
            x1, x2 = port.split('-')
            storeport = list(range(int(x1), int(x2) + 1))
        else:
            storeport.append(int(port))  # Adiciona a porta única à lista como um inteiro
    else:
        print("[*] Forneça portas para escanear.")
    return storeport

def scan_localhost_with_socket(port):
    ip = "127.0.0.1"
    try:
        # Tente estabelecer uma conexão TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            connection = s.connect_ex((ip, port))
            if connection == 0:
                banner = get_banner(port,"tcp")
                print(f"Port {port} is open - {banner[:40]}.")
    except Exception as e:
        print(f"Error scanning port {port}: {e}")       
    
       

def main(target_ip, port_range,scantype):

    flag = []
    open = 0
    closed = 0
    filtered = 0
    

    print("Starting Port scanner v1.0 (developed by: Lucas Giacomini) at - ",datetime.now())

    if target_ip == "127.0.0.1" or target_ip == "localhost":
        for port in port_range:
            scan_localhost_with_socket(port)
        return

    if scantype == "sS":      
        print("[*]Starting SYN Scan")
        for port in port_range:
            flag=scan_port(target_ip, port)
            if flag == "O":
                open = open+1
            if flag == "C":
                closed = closed+1
            if flag == "F":
                filtered = filtered+1

        print(f"\nPort Scanner scan report for {target_ip}:")
        print(f"{open} open ports")  
        print(f"{closed} closed ports")      
        print(f"{filtered} filtered ports")

    if scantype == "sF":
        print("[*]Starting FIN Scan")      
        for port in port_range:
           flag=finscan(target_ip, port)
           if flag == "O":
                open = open+1
           if flag == "F":
                filtered = filtered+1

        print(f"\nPort Scanner scan report for {target_ip}:")
        print(f"{open} open or filtered ports")    
        print(f"{closed} closed ports")      
        print(f"{filtered} filtered ports")
           
           
    if scantype == "sA":
        print("[*]Starting ACK Scan")      
        for port in port_range:
            flag=ackscan(target_ip, port)
            if flag == "C":
                closed = closed+1
            if flag == "F":
                filtered = filtered+1

        print(f"\nPort Scanner scan report for {target_ip}:")
        print(f"{closed} unfiltered ports")      
        print(f"{filtered} filtered ports")

if __name__ == "__main__":
    start_time = timer()
    
    parser = argparse.ArgumentParser(description='Network Port Scanner.')
    parser.add_argument('ip',type=str,help="Endereço IP ou hostname do alvo (ex: python3 portscanner.py 192.168.0.1)")
   
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-sS", action="store_const", const="sS", dest="scantype", help="Syn scan")
    group.add_argument("-sF", action="store_const", const="sF", dest="scantype", help="Fin scan")
    group.add_argument("-sA", action="store_const", const="sA", dest="scantype", help="Ack scan")
    parser.set_defaults(scantype="sS")


    parser.add_argument("-p", "--ports", type=str,dest='port_range',help="Intervalo de portas a ser varridas (ex: 80-1200), default: 1-1024")

    args = parser.parse_args()                

    if args.port_range is not None: #Se o usuario definir um intervalo de portas será processado 
        args.port_range = port_extraction(args.port_range)
    else:
        args.port_range = range(1, 1024)#Se o usuário nao especificar portas será feito do 1 ao 1024

    try:
        main(args.ip, args.port_range,args.scantype)
        end_time = timer()
        executionTime = end_time - start_time
        print("Elapsed time: %.2f seconds" % executionTime)
    except KeyboardInterrupt:
        print("Exiting Port Scanner")
    except Exception as e:
        print(e)
