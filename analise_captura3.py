from scapy.all import rdpcap
from collections import Counter, defaultdict
import os

# ============================================================================
# QUESTÃO 3 - Análise do arquivo de captura captura3-1.pcap e captura3-2.pcap
# ============================================================================
# Implemente um código em Python, utilizando a biblioteca Scapy, para analisar os arquivos de captura
# captura3-1.pcap e captura3-2.pcap. Em seguida,
# responda:
#
# (a) Apresente estatísticas sobre os IPs de origem e
# destino das capturas
# (b) Apresente estatísticas sobre as portas de origem e
# destino das capturas.
# (c) Estas capturas representam capturas de um tr´afego
# de redes que passam por um roteador fazendo
# NAT (Network Address Translation). Estas s˜ao
# realizadas antes e depois do roteador. Com base
# nisto, responda:
#   i. Qual é o IP de origem e de destino antes e
#   após a tradução do NAT.
#   ii. Qual são as portas de origem e de destino
#   antes e após a tradução do NAT.
#   iii. Justifique suas respostas a
# ============================================================================


def extract_flow_info(pkt):
    try:
        if pkt.haslayer('IP'):
            proto = None
            sport = None
            dport = None
            if pkt.haslayer('TCP'):
                proto = 'TCP'
                sport = pkt['TCP'].sport
                dport = pkt['TCP'].dport
            elif pkt.haslayer('UDP'):
                proto = 'UDP'
                sport = pkt['UDP'].sport
                dport = pkt['UDP'].dport
            else:
                proto = 'IP'

            return (proto, pkt['IP'].src, sport, pkt['IP'].dst, dport)
        elif pkt.haslayer('ARP'):
            return ('ARP', pkt['ARP'].psrc, None, pkt['ARP'].pdst, None)
    except Exception:
        return None
    return None


def analisar_captura(pre_path, post_path, limit=None):
    # verificar arquivos
    if not os.path.exists(pre_path):
        print(f"Erro: arquivo {pre_path} não encontrado!")
        return False
    if not os.path.exists(post_path):
        print(f"Erro: arquivo {post_path} não encontrado!")
        return False

    pre_pkts = rdpcap(pre_path)
    post_pkts = rdpcap(post_path)

    total_pre = len(pre_pkts)
    total_post = len(post_pkts)

    if limit is None or limit <= 0:
        limit = max(total_pre, total_post)

    print("=" * 80)
    print("QUESTÃO 3 - ANÁLISE DE CAPTURAS ANTES/DEPOIS DO ROTEADOR (NAT)")
    print(f"Arquivos: pre={pre_path}, post={post_path}")
    print(f"Pacotes: pre={total_pre}, post={total_post}\n")

    # Estatísticas por captura
    def stats(pkts, cap_name):
        src_ips = Counter()
        dst_ips = Counter()
        src_ports = Counter()
        dst_ports = Counter()
        proto = Counter()
        for pkt in pkts:
            info = extract_flow_info(pkt)
            if not info:
                continue
            pproto, sip, sport, dip, dport = info
            proto[pproto] += 1
            if sip:
                src_ips[sip] += 1
            if dip:
                dst_ips[dip] += 1
            if sport is not None:
                src_ports[sport] += 1
            if dport is not None:
                dst_ports[dport] += 1

        print(f"--- Estatísticas ({cap_name}) ---")
        print(f"Protocolos: {', '.join(f'{k}:{v}' for k,v in proto.most_common())}")
        print(f"IPs de origem:")
        for ip, c in src_ips.most_common(10):
            print(f"  {ip}: {c}")
        print(f"IPs de destino:")
        for ip, c in dst_ips.most_common(10):
            print(f"  {ip}: {c}")
        print(f"Portas de origem:")
        for p, c in src_ports.most_common(10):
            print(f"  {p}: {c}")
        print(f"Portas de destino:")
        for p, c in dst_ports.most_common(10):
            print(f"  {p}: {c}")
        print("")

        return {
            'src_ips': src_ips,
            'dst_ips': dst_ips,
            'src_ports': src_ports,
            'dst_ports': dst_ports,
            'proto': proto,
        }

    pre_stats = stats(pre_pkts, 'antes (captura3-1)')
    post_stats = stats(post_pkts, 'depois (captura3-2)')

    # Tentar inferir mapeamentos NAT
    # Construir listas de fluxos (apenas TCP/UDP) com campos relevantes
    def build_flows(pkts):
        flows = []
        for i, pkt in enumerate(pkts):
            info = extract_flow_info(pkt)
            if not info:
                continue
            proto, sip, sport, dip, dport = info
            if proto in ('TCP', 'UDP'):
                flows.append({'idx': i, 'proto': proto, 'sip': sip, 'sport': sport, 'dip': dip, 'dport': dport})
        return flows

    flows_pre = build_flows(pre_pkts)
    flows_post = build_flows(post_pkts)

    # Indexar post flows por (proto,dst_ip,dst_port) para busca rápida
    post_index = defaultdict(list)
    for f in flows_post:
        key = (f['proto'], f['dip'], f['dport'])
        post_index[key].append(f)

    # Mapeamentos candidatos: pre (sip:sport) -> post (sip:sport)
    mapping_counter = Counter()
    mapping_examples = {}

    for f in flows_pre:
        key = (f['proto'], f['dip'], f['dport'])
        candidates = post_index.get(key, [])
        # se houver candidatos, escolhe o primeiro diferente de f (se possível)
        for cand in candidates:
            # geralmente o que muda é o sip/sport (NAT), dst permanece
            if cand['sip'] != f['sip'] or cand['sport'] != f['sport']:
                left = f"{f['sip']}:{f['sport']}"
                right = f"{cand['sip']}:{cand['sport']}"
                mapping_counter[(left, right)] += 1
                if (left, right) not in mapping_examples:
                    mapping_examples[(left, right)] = (f, cand)
                break

    print("--- Mapeamentos NAT candidatos (pre -> post) e contagem de ocorrências ---")
    if mapping_counter:
        for (left, right), cnt in mapping_counter.most_common(20):
            print(f"  {left}  ->  {right}: {cnt} pacote(s)")
    else:
        print("  Nenhum mapeamento NAT claro detectado.")

    print("\n--- Exemplos de mapeamentos encontrados ---")
    for (left, right), pair in list(mapping_examples.items())[:10]:
        pre_f, post_f = pair
        print(f"  {left} -> {right}   (proto={pre_f['proto']}, dst={pre_f['dip']}:{pre_f['dport']})")

    print("=" * 80)
    return True


if __name__ == '__main__':
    analisar_captura('./capturas/captura3-1.pcap', './capturas/captura3-2.pcap')
