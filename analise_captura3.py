#!/usr/bin/env python3
# analise_captura3.py
#
# Análise de duas capturas PCAP (antes e depois do NAT)
# Usado para responder a Questão 3 do trabalho.

from scapy.all import rdpcap
from collections import Counter, defaultdict

# Arquivos PCAP (ajuste o caminho caso necessário)
PCAP_ANTES = "capturas/captura3-1.pcap"   # tráfego antes do roteador (rede interna)
PCAP_DEPOIS = "capturas/captura3-2.pcap"  # tráfego depois do roteador (rede externa)

# -----------------------------------------------------------
# Função que calcula estatísticas de IP e portas
# -----------------------------------------------------------
def estatisticas_ip_portas(pacotes):
    """
    Retorna contadores:
    - IPs de origem
    - IPs de destino
    - Portas de origem (TCP/UDP)
    - Portas de destino (TCP/UDP)
    """
    ips_origem = Counter()
    ips_destino = Counter()
    portas_origem = Counter()
    portas_destino = Counter()

    for p in pacotes:
        if p.haslayer("IP"):
            ips_origem[p['IP'].src] += 1
            ips_destino[p['IP'].dst] += 1

            # Se for TCP
            if p.haslayer("TCP"):
                portas_origem[p['TCP'].sport] += 1
                portas_destino[p['TCP'].dport] += 1
            
            # Se for UDP
            elif p.haslayer("UDP"):
                portas_origem[p['UDP'].sport] += 1
                portas_destino[p['UDP'].dport] += 1

    return ips_origem, ips_destino, portas_origem, portas_destino


# -----------------------------------------------------------
# Tentativa de inferir como o NAT alterou IP/portas
# -----------------------------------------------------------
def inferir_nat(pacotes_antes, pacotes_depois):
    """
    Tenta identificar qual IP/porta interna virou qual IP/porta externa.
    Usa uma heurística baseada em:
    - Mesmo IP de destino
    - Mesma porta de destino
    - Mesmo tamanho de payload
    """
    mapeamentos = Counter()

    # Indexa pacotes "depois" por (destino, porta destino, tamanho payload)
    indice_depois = defaultdict(list)
    for p in pacotes_depois:
        if p.haslayer("IP"):
            dst = p['IP'].dst
            if p.haslayer("TCP"):
                dport = p['TCP'].dport
                tamanho = len(p['TCP'].payload)
                indice_depois[(dst, dport, tamanho)].append(p)

            elif p.haslayer("UDP"):
                dport = p['UDP'].dport
                tamanho = len(p['UDP'].payload)
                indice_depois[(dst, dport, tamanho)].append(p)

    # Para cada pacote "antes", tenta achar o correspondente "depois"
    for p in pacotes_antes:
        if p.haslayer("IP"):
            ip_origem_antes = p['IP'].src

            if p.haslayer("TCP"):
                porta_origem_antes = p['TCP'].sport
                porta_destino = p['TCP'].dport
                tamanho = len(p['TCP'].payload)

                chave = (p['IP'].dst, porta_destino, tamanho)
                candidatos = indice_depois.get(chave, [])

                for c in candidatos:
                    ip_traduzido = c['IP'].src
                    porta_traduzida = c['TCP'].sport
                    mapeamentos[((ip_origem_antes, porta_origem_antes), 
                                 (ip_traduzido, porta_traduzida))] += 1

            elif p.haslayer("UDP"):
                porta_origem_antes = p['UDP'].sport
                porta_destino = p['UDP'].dport
                tamanho = len(p['UDP'].payload)

                chave = (p['IP'].dst, porta_destino, tamanho)
                candidatos = indice_depois.get(chave, [])

                for c in candidatos:
                    ip_traduzido = c['IP'].src
                    porta_traduzida = c['UDP'].sport
                    mapeamentos[((ip_origem_antes, porta_origem_antes), 
                                 (ip_traduzido, porta_traduzida))] += 1

    return mapeamentos


# -----------------------------------------------------------
# Impressão formatada dos contadores
# -----------------------------------------------------------
def imprimir_top(contador, titulo, top=10):
    print(titulo)
    for k, v in contador.most_common(top):
        print(f"  {k}: {v}")
    print()


# -----------------------------------------------------------
# PROGRAMA PRINCIPAL
# -----------------------------------------------------------
def main():
    # Lendo os PCAPs
    antes = rdpcap(PCAP_ANTES)
    depois = rdpcap(PCAP_DEPOIS)

    print(f"Analisando:\n - {PCAP_ANTES} (antes do NAT)\n - {PCAP_DEPOIS} (depois do NAT)\n")

    print(f"Número de pacotes (antes): {len(antes)}")
    print(f"Número de pacotes (depois): {len(depois)}\n")

    # Estatísticas dos dois arquivos
    a_src, a_dst, a_psrc, a_pdst = estatisticas_ip_portas(antes)
    d_src, d_dst, d_psrc, d_pdst = estatisticas_ip_portas(depois)

    print("========== ESTATÍSTICAS (ANTES DO NAT) ==========")
    imprimir_top(a_src, "IPs de origem (antes):")
    imprimir_top(a_dst, "IPs de destino (antes):")
    imprimir_top(a_psrc, "Portas de origem (antes):")
    imprimir_top(a_pdst, "Portas de destino (antes):")

    print("========== ESTATÍSTICAS (DEPOIS DO NAT) ==========")
    imprimir_top(d_src, "IPs de origem (depois):")
    imprimir_top(d_dst, "IPs de destino (depois):")
    imprimir_top(d_psrc, "Portas de origem (depois):")
    imprimir_top(d_pdst, "Portas de destino (depois):")

    # Tentativa de inferir o NAT
    print("========== TENTATIVA DE IDENTIFICAR O NAT ==========")
    mapeamentos = inferir_nat(antes, depois)

    if mapeamentos:
        for ((ip_int, porta_int), (ip_ext, porta_ext)), qtd in mapeamentos.most_common(20):
            print(f"  {ip_int}:{porta_int}  ->  {ip_ext}:{porta_ext}  (ocorrências: {qtd})")
    else:
        print("Nenhum mapeamento inferido automaticamente.")


if __name__ == "__main__":
    main()
