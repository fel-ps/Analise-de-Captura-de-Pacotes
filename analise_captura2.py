#!/usr/bin/env python3
# analise_captura2.py
#
# Análise de uma captura PCAP para identificar sequência de pacotes
# e estatísticas de protocolos — usado na Questão 2 do trabalho.

from scapy.all import rdpcap
from collections import Counter

# Arquivo PCAP a ser analisado
PCAP_FILE = "capturas/captura2.pcap"


# -----------------------------------------------------------
# Função: imprime um resumo da sequência de pacotes
# -----------------------------------------------------------
def resumo_sequencia_pacotes(pacotes, limite=200):
    """
    Exibe os primeiros 'limite' pacotes da captura.
    Para cada pacote, imprime:
    - índice
    - timestamp
    - IP origem → destino
    - protocolo (TCP/UDP/ICMP)
    - portas e flags no caso de TCP
    """

    for i, p in enumerate(pacotes):
        if i >= limite:
            break

        tempo = getattr(p, "time", 0)
        protocolo = "?"
        info = ""

        if p.haslayer("IP"):
            src = p["IP"].src
            dst = p["IP"].dst

            # Pacote TCP
            if p.haslayer("TCP"):
                protocolo = "TCP"
                info = (
                    f"{p['TCP'].sport} -> {p['TCP'].dport} "
                    f"flags={p['TCP'].flags} "
                    f"len={len(p['TCP'].payload)}"
                )

            # Pacote UDP
            elif p.haslayer("UDP"):
                protocolo = "UDP"
                info = (
                    f"{p['UDP'].sport} -> {p['UDP'].dport} "
                    f"len={len(p['UDP'].payload)}"
                )

            # Pacote ICMP
            elif p.haslayer("ICMP"):
                protocolo = "ICMP"
            
            # Qualquer outro protocolo IP
            else:
                protocolo = p.lastlayer().name

            print(f"{i:04d} t={tempo:.6f} {src} -> {dst} {protocolo} {info}")

        else:
            # Pacote não-IP (ARP, LLC etc.)
            print(f"{i:04d} NON-IP {p.summary()}")


# -----------------------------------------------------------
# Função: estatísticas de protocolos
# -----------------------------------------------------------
def estatisticas_protocolos(pacotes):
    """
    Conta quantos pacotes existem de cada protocolo.
    """
    cont = Counter()

    for p in pacotes:
        if p.haslayer("TCP"):
            cont["TCP"] += 1
        elif p.haslayer("UDP"):
            cont["UDP"] += 1
        elif p.haslayer("ICMP"):
            cont["ICMP"] += 1
        elif p.haslayer("ARP"):
            cont["ARP"] += 1
        else:
            cont[p.lastlayer().name] += 1

    return cont


# -----------------------------------------------------------
# PROGRAMA PRINCIPAL
# -----------------------------------------------------------
def main():
    pacotes = rdpcap(PCAP_FILE)

    print(f"Arquivo carregado: {PCAP_FILE}")
    print(f"Número total de pacotes: {len(pacotes)}\n")

    # Sequência dos primeiros pacotes
    print("=== Sequência de pacotes (primeiros 200) ===")
    resumo_sequencia_pacotes(pacotes, limite=200)

    # Estatísticas por protocolo
    print("\n=== Estatísticas por protocolo ===")
    stats = estatisticas_protocolos(pacotes)
    for proto, qtd in stats.most_common():
        print(f"  {proto}: {qtd} pacotes")

    # Estatísticas de portas TCP/UDP
    print("\n=== Principais portas (origem e destino) ===")
    portas_origem = Counter()
    portas_destino = Counter()

    for p in pacotes:
        if p.haslayer("TCP"):
            portas_origem[p['TCP'].sport] += 1
            portas_destino[p['TCP'].dport] += 1
        if p.haslayer("UDP"):
            portas_origem[p['UDP'].sport] += 1
            portas_destino[p['UDP'].dport] += 1

    print("Top 10 portas de origem:")
    for porta, qtd in portas_origem.most_common(10):
        print(f"  {porta}: {qtd}")

    print("\nTop 10 portas de destino:")
    for porta, qtd in portas_destino.most_common(10):
        print(f"  {porta}: {qtd}")


if __name__ == "__main__":
    main()
