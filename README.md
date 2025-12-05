# Análise de Captura de Pacotes

## 📋 Descrição

Este projeto contém scripts em Python para análise detalhada de arquivos de captura de tráfego de rede (arquivos `.pcap`). Utiliza a biblioteca **Scapy** para inspecionar, dessecar e extrair informações de pacotes de rede, respondendo a questões específicas sobre tipos de comunicação, endereços envolvidos, protocolos utilizados e análise de NAT.

## 📁 Estrutura do Projeto

```
Analise-de-Captura-de-Pacotes/
├── analise_captura1.py          # Análise da captura 1
├── analise_captura2.py          # Análise da captura 2
├── analise_captura3.py          # Análise das capturas 3 (NAT)
├── capturas/
│   ├── captura1.pcap            # Arquivo de captura 1
│   ├── captura2.pcap            # Arquivo de captura 2
│   ├── captura3-1.pcap          # Arquivo de captura 3 (antes do NAT)
│   └── captura3-2.pcap          # Arquivo de captura 3 (depois do NAT)
├── README.md                     # Este arquivo
└── LICENSE                       # Licença do projeto
```

## 🎯 Funcionalidades

### 📊 analise_captura1.py
Análise completa do arquivo `captura1.pcap`:
- **Tipo de comunicação**: Identifica o tipo de tráfego (TCP, UDP, ICMP, ARP, etc.)
- **Endereços envolvidos**: Lista todos os endereços IP e MAC de origem e destino
- **Quantidade de pacotes**: Conta o total de pacotes capturados
- **Protocolo dominante**: Mostra qual protocolo foi mais utilizado
- **Portas utilizadas**: Analisa as portas TCP/UDP mais comuns

**Como usar:**
```bash
python analise_captura1.py
```

### 📈 analise_captura2.py
Análise detalhada do arquivo `captura2.pcap`:
- **Sequência de pacotes**: Exibe a sequência de pacotes capturados com timestamps
- **Estatísticas gerais**: Contagem de protocolos, IPs, MACs e portas
- **Distribuição de tamanhos**: Analisa os tamanhos mais comuns de pacotes
- **Top 10 endereços**: Mostra os 10 endereços mais ativos (origem e destino)

**Como usar:**
```bash
python analise_captura2.py
```

### 🔄 analise_captura3.py
Análise comparativa de capturas antes/depois de um roteador com NAT:
- **Estatísticas de IPs**: Compara IPs antes e depois da tradução
- **Estatísticas de portas**: Analisa mudanças nas portas de origem/destino
- **Mapeamentos NAT**: Identifica quais IPs e portas foram traduzidos
- **Justificativas**: Explica as mudanças observadas
- **Análise de fluxos**: Rastreia fluxos de pacotes através do roteador

**Como usar:**
```bash
python analise_captura3.py
```

## 🛠️ Requisitos

### Dependências Python
- **Python 3.6+**
- **Scapy** (3.0+): Análise de pacotes de rede

### Instalação

1. Clone o repositório:
```bash
git clone https://github.com/fel-ps/Analise-de-Captura-de-Pacotes.git
cd Analise-de-Captura-de-Pacotes
```

2. Instale as dependências:
```bash
pip install scapy
```

3. Certifique-se de que os arquivos `.pcap` estão no diretório `capturas/`

## 📖 Saída dos Scripts

Cada script gera uma análise formatada com as seguintes informações:

### Exemplo de Saída - analise_captura1.py
```
================================================================================
ANÁLISE DA CAPTURA DE REDE - captura1.pcap
================================================================================

(C) TOTAL DE PACOTES CAPTURADOS: 150

(B) ENDEREÇOS ENVOLVIDOS:

--- Endereços IP de Origem ---
  192.168.1.100: 75 pacotes
  ...

--- Protocolos Utilizados ---
  TCP: 100 pacotes (66.7%)
  UDP: 50 pacotes (33.3%)
```

## 🔍 Conceitos de Rede Analisados

- **Protocolos**: TCP, UDP, ICMP, ARP, IP, Ethernet
- **Camadas OSI**: Análise de múltiplas camadas (camada 2, 3, 4)
- **NAT (Network Address Translation)**: Rastreamento de tradução de endereços
- **Fluxos de rede**: Identificação de conexões entre origem e destino
- **Endereçamento**: IPv4, MAC address

## 💡 Exemplos de Uso Avançado

### Limitar análise de captura2.py aos primeiros 50 pacotes
Edite o arquivo e altere a chamada da função:
```python
analisar_captura('./capturas/captura2.pcap', limit=50)
```

### Analisar capturas personalizadas
Para analisar seus próprios arquivos `.pcap`, modifique os caminhos nos scripts:
```python
analisar_captura('./seu_arquivo.pcap')
```

## 📝 Perguntas Respondidas

Os scripts respondem às seguintes questões:

1. **Captura 1**: 
   - De que se trata a comunicação?
   - Quais são os endereços envolvidos?
   - Quantos pacotes foram capturados?

2. **Captura 2**:
   - Qual é a sequência de pacotes capturados?
   - Quais são as estatísticas de pacotes e protocolo?

3. **Capturas 3**:
   - Qual é o mapeamento NAT (antes/depois)?
   - Como as portas mudam através do roteador?
   - Como os IPs são traduzidos?

## 🤝 Contribuições

Contribuições são bem-vindas! Sinta-se livre para:
- Abrir issues para bugs ou melhorias
- Enviar pull requests com novas funcionalidades
- Sugerir otimizações

## 📄 Licença

Este projeto está licenciado sob a [LICENSE](LICENSE) fornecida.

## 👤 Autores

Desenvolvido por:
**fel-ps** e
**SoutoCB**

## ⚠️ Notas Importantes

- Os scripts devem ser executados com os arquivos `.pcap` presentes no diretório `capturas/`
- Certifique-se de ter permissões adequadas para ler os arquivos de captura
- A biblioteca Scapy requer privilégios elevados em alguns sistemas para capturar pacotes ao vivo
- Os arquivos `.pcap` são específicos para análise offline

## 📚 Referências

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Wireshark](https://www.wireshark.org/) - Ferramenta complementar para análise
- [RFC 3022 - Traditional IP Network Address Translator](https://tools.ietf.org/html/rfc3022)

---

**Última atualização**: Dezembro de 2025
