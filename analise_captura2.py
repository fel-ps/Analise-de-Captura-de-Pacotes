import os
from collections import Counter
from scapy.all import *

# ============================================================================
# QUESTÃO 2 - Análise do arquivo de captura captura2.pcap
# ============================================================================
# Implemente um código em Python, utilizando a biblioteca Scapy, 
# para analisar o arquivo de captura captura2.pcap.
# Em seguida, responda:
# (a) Descreva o que foi capturado neste tráfego de rede
# e apresente, por meio da sequência de pacotes, de
# que se trata esta captura.
# (b) Apresente estatísticas sobre a quantidade e tipo
# de pacotes capturados.

def analisar_captura(arquivo_pcap, limit=None):

    # Verificar se o arquivo existe
    if not os.path.exists(arquivo_pcap):
        print(f"Erro: arquivo {arquivo_pcap} não encontrado!")
        return False

    # Carregar pacotes
    packets = rdpcap(arquivo_pcap)
    total_packets = len(packets)

    # Ajustar limite
    if limit is None or limit <= 0 or limit > total_packets:
        limit = total_packets

    print("=" * 80)
    print("ANÁLISE DA CAPTURA DE REDE - captura2.pcap")
    print("=" * 80)

    # (a) Sequência de pacotes — mostrar os primeiros `limit` pacotes com timestamp e summary
    print("\n(a) SEQUÊNCIA DE PACOTES (mostrando os primeiros {} pacotes):".format(limit))
    for i, pkt in enumerate(packets[:limit], start=1):
        ts = getattr(pkt, 'time', None)
        timestr = f"{ts:.6f}" if ts is not None else "-"
        try:
            summary = pkt.summary()
        except Exception:
            summary = "(erro no summary)"
        print(f"#{i:04d}  {timestr}  {summary}")

    # (b) Estatísticas
    print("\n" + "=" * 80)
    print("(b) ESTATÍSTICAS GERAIS")

    # inicializando contadores
    proto = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    src_macs = Counter()
    dst_macs = Counter()
    tcp_ports = Counter()
    udp_ports = Counter()
    sizes = Counter()

    for pkt in packets:
        sizes[len(bytes(pkt))] += 1
        if pkt.haslayer('Ether'):
            proto['Ether'] += 1
            src_macs[pkt['Ether'].src] += 1
            dst_macs[pkt['Ether'].dst] += 1
        if pkt.haslayer('ARP'):
            proto['ARP'] += 1
        if pkt.haslayer('IP'):
            proto['IP'] += 1
            src_ips[pkt['IP'].src] += 1
            dst_ips[pkt['IP'].dst] += 1
            if pkt.haslayer('TCP'):
                proto['TCP'] += 1
                tcp_ports[f"{pkt['TCP'].sport} -> {pkt['TCP'].dport}"] += 1
            elif pkt.haslayer('UDP'):
                proto['UDP'] += 1
                udp_ports[f"{pkt['UDP'].sport} -> {pkt['UDP'].dport}"] += 1
            elif pkt.haslayer('ICMP'):
                proto['ICMP'] += 1
        # outros protocolos serão contabilizados como 'Outro' se necessário

    # imprimir estatísticas resumidas
    print(f"Total de pacotes no arquivo: {total_packets}")
    print("\n--- Protocolos (contagem de pacotes que contêm cada protocolo) ---")
    for p, c in proto.most_common():
        pct = (c / total_packets) * 100 if total_packets > 0 else 0
        print(f"  {p}: {c} pacotes ({pct:.1f}%)")

    print("\n--- IPs de origem ---")
    for ip, c in src_ips.most_common(10):
        print(f"  {ip}: {c} pacotes")

    print("\n--- IPs de destino ---")
    for ip, c in dst_ips.most_common(10):
        print(f"  {ip}: {c} pacotes")

    print("\n--- MACs de origem ---")
    for m, c in src_macs.most_common(10):
        print(f"  {m}: {c} pacotes")

    print("\n--- MACs de destino ---")
    for m, c in dst_macs.most_common(10):
        print(f"  {m}: {c} pacotes")

    print("\n--- Portas TCP (origem -> destino) ---")
    for p, c in tcp_ports.most_common(10):
        print(f"  {p}: {c} pacotes")

    print("\n--- Portas UDP (origem -> destino) ---")
    for p, c in udp_ports.most_common(10):
        print(f"  {p}: {c} pacotes")

    print("\n--- Tamanhos de pacote mais comuns (bytes) ---")
    for s, c in sizes.most_common(10):
        print(f"  {s} bytes: {c} pacotes")

    return True


if __name__ == '__main__':
    analisar_captura('./capturas/captura2.pcap')
