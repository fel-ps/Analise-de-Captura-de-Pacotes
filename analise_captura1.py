#!/usr/bin/env python3
# analise_captura1.py — Versão traduzida e comentada
# Objetivo: analisar uma captura .pcap extraindo estatísticas essenciais
# Uso: python3 analise_captura1.py

from scapy.all import rdpcap
from collections import Counter

# Caminho do arquivo PCAP
PCAP_FILE = "capturas/captura1.pcap"

def detect_top_layers(packets, top_n=5):
    """
    Identifica as camadas (protocolos) mais comuns.
    Exemplo: Ethernet, IP, TCP, UDP, ARP, ICMP etc.
    """
    cnt = Counter()
    for p in packets:
        # Obtém todas as camadas do pacote
        layers = [l.name for l in p.layers()]
        for l in layers:
            cnt[l] += 1
    return cnt.most_common(top_n)

def detect_common_ports(packets, top_n=10):
    """
    Detecta as portas mais comuns de origem e destino
    para tráfego TCP e UDP.
    """
    sport = Counter()   # portas de origem
    dport = Counter()   # portas de destino

    for p in packets:
        if p.haslayer("TCP"):
            sport[p["TCP"].sport] += 1
            dport[p["TCP"].dport] += 1
        elif p.haslayer("UDP"):
            sport[p["UDP"].sport] += 1
            dport[p["UDP"].dport] += 1

    return sport.most_common(top_n), dport.most_common(top_n)

def unique_addresses(packets):
    """
    Conta quantos pacotes cada endereço IP enviou (origem)
    e quantos recebeu (destino).
    """
    src = Counter()
    dst = Counter()

    for p in packets:
        if p.haslayer("IP"):
            src[p["IP"].src] += 1
            dst[p["IP"].dst] += 1

    return src, dst

def main():
    # Carrega os pacotes do arquivo .pcap
    packets = rdpcap(PCAP_FILE)

    print(f"Arquivo analisado: {PCAP_FILE}")
    print(f"Número total de pacotes capturados: {len(packets)}\n")

    # --- Topo das camadas ---
    print("Camadas mais frequentes (Top Layers):")
    for name, count in detect_top_layers(packets):
        print(f"  {name}: {count}")
    print()

    # --- Endereços IP ---
    src, dst = unique_addresses(packets)

    print("Endereços de origem mais frequentes:")
    for ip, c in src.most_common(10):
        print(f"  {ip}: {c} pacotes")
    print()

    print("Endereços de destino mais frequentes:")
    for ip, c in dst.most_common(10):
        print(f"  {ip}: {c} pacotes")
    print()

    # --- Portas ---
    tcp_sport, tcp_dport = detect_common_ports(packets)

    if tcp_sport or tcp_dport:
        print("Portas de ORIGEM mais comuns:")
        for p, c in tcp_sport:
            print(f"  {p}: {c}")
        print()

        print("Portas de DESTINO mais comuns:")
        for p, c in tcp_dport:
            print(f"  {p}: {c}")
        print()

    # --- Sugestão de tipo de comunicação ---
    print("Sugestão do tipo de tráfego (heurística):")

    top_layers = detect_top_layers(packets, top_n=8)
    layer_names = [t[0] for t in top_layers]

    # Heurística baseada em camadas e portas
    if "HTTP" in layer_names or any(port in [80, 443] for port,_ in tcp_dport):
        print("  Possível tráfego HTTP/HTTPS (portas 80 ou 443 detectadas).")
    elif "DNS" in layer_names or any(port == 53 for port,_ in tcp_dport):
        print("  Possível tráfego DNS (porta 53 detectada).")
    elif "ARP" in layer_names:
        print("  Tráfego de resolução de endereços (ARP).")
    elif "ICMP" in layer_names:
        print("  Tráfego ICMP detectado (possível ping – echo-request/echo-reply).")
    else:
        print("  Tipo de tráfego não evidente — verificar packet.show().")


if __name__ == "__main__":
    main()
