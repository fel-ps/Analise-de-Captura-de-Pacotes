from scapy.all import *
from collections import Counter
import os

# ============================================================================
# QUESTÃO 1 - Análise do arquivo de captura captura1.pcap
# ============================================================================
# Implemente um código em Python, utilizando a biblioteca Scapy, 
# para analisar o arquivo de captura captura1.pcap.
# Em seguida, responda:
# (a) De que se trata esta comunicação.
# (b) Quais são os endereços envolvidos.
# (c) Quantos pacotes são enviados neste tráfego de rede.
# ============================================================================

def analisar_captura(arquivo_pcap):
    
    # Verificar se o arquivo existe
    if not os.path.exists(arquivo_pcap):
        print(f"Erro: arquivo {arquivo_pcap} não encontrado!")
        return False
    
    # Carregar os pacotes do arquivo de captura
    packets = rdpcap(arquivo_pcap)
    
    print("=" * 80)
    print("ANÁLISE DA CAPTURA DE REDE - captura1.pcap")
    print("=" * 80)
    
    # ========================================================================
    # (C) Quantos pacotes são enviados neste tráfego de rede
    # ========================================================================
    total_packets = len(packets)
    print(f"\n(C) TOTAL DE PACOTES CAPTURADOS: {total_packets}")
    
    # ========================================================================
    # (B) Quais são os endereços envolvidos
    # ========================================================================
    src_ips = Counter()
    dst_ips = Counter()
    src_macs = Counter()
    dst_macs = Counter()
    protocols = Counter()
    
    for packet in packets:
        # Contabilizar IPs
        if packet.haslayer("IP"):
            src_ips[packet['IP'].src] += 1
            dst_ips[packet['IP'].dst] += 1
        
        # Contabilizar MACs
        if packet.haslayer("Ether"):
            src_macs[packet['Ether'].src] += 1
            dst_macs[packet['Ether'].dst] += 1
        
        # Contabilizar protocolos
        if packet.haslayer("IP"):
            if packet.haslayer("TCP"):
                protocols["TCP"] += 1
            elif packet.haslayer("UDP"):
                protocols["UDP"] += 1
            elif packet.haslayer("ICMP"):
                protocols["ICMP"] += 1
            else:
                protocols["Outro"] += 1
        elif packet.haslayer("ARP"):
            protocols["ARP"] += 1
        else:
            protocols["Outro"] += 1
    
    print("\n(B) ENDEREÇOS ENVOLVIDOS:")
    print("\n--- Endereços IP de Origem ---")
    for ip, count in sorted(src_ips.items()):
        print(f"  {ip}: {count} pacotes")
    
    print("\n--- Endereços IP de Destino ---")
    for ip, count in sorted(dst_ips.items()):
        print(f"  {ip}: {count} pacotes")
    
    print("\n--- Endereços MAC de Origem ---")
    for mac, count in sorted(src_macs.items()):
        print(f"  {mac}: {count} pacotes")
    
    print("\n--- Endereços MAC de Destino ---")
    for mac, count in sorted(dst_macs.items()):
        print(f"  {mac}: {count} pacotes")
    
    # ========================================================================
    # (A) De que se trata esta comunicação
    # ========================================================================
    print("\n(A) TIPO DE COMUNICAÇÃO:")
    print("\n--- Protocolos Utilizados ---")
    for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_packets) * 100
        print(f"  {proto}: {count} pacotes ({percentage:.1f}%)")
    
    # Análise adicional por protocolo
    print("\n--- Análise Detalhada por Protocolo ---")
    
    tcp_count = sum(1 for p in packets if p.haslayer("TCP"))
    if tcp_count > 0:
        print(f"\nTCP: {tcp_count} pacotes")
        tcp_ports = Counter()
        for packet in packets:
            if packet.haslayer("TCP"):
                tcp_ports[f"{packet['TCP'].sport} -> {packet['TCP'].dport}"] += 1
        print("  Portas utilizadas (origem -> destino):")
        for ports, count in tcp_ports.most_common(5):
            print(f"    {ports}: {count} pacotes")
    
    udp_count = sum(1 for p in packets if p.haslayer("UDP"))
    if udp_count > 0:
        print(f"\nUDP: {udp_count} pacotes")
        udp_ports = Counter()
        for packet in packets:
            if packet.haslayer("UDP"):
                udp_ports[f"{packet['UDP'].sport} -> {packet['UDP'].dport}"] += 1
        print("  Portas utilizadas (origem -> destino):")
        for ports, count in udp_ports.most_common(5):
            print(f"    {ports}: {count} pacotes")
    
    icmp_count = sum(1 for p in packets if p.haslayer("ICMP"))
    if icmp_count > 0:
        print(f"\nICMP: {icmp_count} pacotes")
    
    arp_count = sum(1 for p in packets if p.haslayer("ARP"))
    if arp_count > 0:
        print(f"\nARP: {arp_count} pacotes")
    
    # Resumo geral
    print("\n" + "=" * 80)
    print("RESUMO GERAL")
    print("=" * 80)
    print(f"Total de pacotes: {total_packets}")
    print(f"Quantidade de IPs de origem únicos: {len(src_ips)}")
    print(f"Quantidade de IPs de destino únicos: {len(dst_ips)}")
    print(f"Quantidade de MACs de origem únicos: {len(src_macs)}")
    print(f"Quantidade de MACs de destino únicos: {len(dst_macs)}")
    print("=" * 80)
    
    return True

if __name__ == "__main__":
    analisar_captura("./capturas/captura1.pcap")
