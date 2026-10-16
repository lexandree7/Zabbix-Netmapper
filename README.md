# Network mapper: módulo para Zabbix 7.0 LTS

Mapeamento interativo da topologia física de redes IT/OT. A partir de um prefixo ou faixa de IPs, o módulo:

1. **Varre** o prefixo e encontra os IPs ativos (ICMP via fping, TCP connect, SNMP e cache ARP). A varredura sai do servidor do frontend ou de um **proxy Zabbix** à escolha do usuário.
2. **Cruza com o Zabbix**. IP que já pertence a um host aparece como o host; IP sem host aparece com ícone genérico e um botão **+** para adicioná-lo.
3. **Identifica** cada equipamento por HTTP/HTTPS (título, cabeçalho Server, certificado), banners SSH e Telnet (sem login), SNMP (sysDescr, ENTITY-MIB, MACs, BRIDGE-MIB) e EtherNet/IP ListIdentity.
4. **Localiza vizinhos** de switches:
   - LLDP (e CDP no Cisco/Stratix) desenha as conexões com as interfaces dos dois lados.
   - Na tabela MAC, uma porta com **exatamente um MAC** e sem vizinho LLDP/CDP é tratada como **porta de acesso** e ligada ao equipamento dono daquele MAC (identificado por MAC ou por ARP).
5. **Constrói o mapa em etapas.** Cada ação do usuário acrescenta nós e conexões. O mapa pode ser exportado como **mapa nativo do Zabbix** ou como JSON.

## Instalação

```bash
# <frontend> é normalmente /usr/share/zabbix (pacotes oficiais 7.0)
cp -r zabbix-netmapper <frontend>/modules/netmapper
chown -R root:root <frontend>/modules/netmapper
```

1. Em **Administration → General → Modules**, clique em **Scan directory** e habilite **Network mapper**.
2. O menu aparece em **Monitoring → Network mapper**.
3. Para restringir quem usa o módulo, ajuste o perfil em **Users → User roles → Access to UI elements → Modules**. Além disso, as actions exigem usuário do tipo **Admin** ou **Super admin**.

### Requisitos do servidor do frontend

| Item | Uso | Obrigatório |
|---|---|---|
| PHP `sockets` | TCP connect paralelo, cliente SNMP v1/v2c próprio | Sim (já é requisito do frontend Zabbix) |
| PHP `mbstring`, `openssl` | Tratamento de texto, HTTPS | Sim (já são requisitos) |
| `fping` (`/usr/sbin/fping`) | Probe ICMP | Não: sem ele, o probe ICMP é ignorado |
| PHP `snmp` (php-snmp) | Somente para **SNMPv3** | Não |
| `exec()` habilitado | Execução do fping | Não |
| Linux `/proc/net/arp` legível | Detecção por ARP no mesmo segmento L2 | Não |

## Uso

1. **Prefixo/faixa:** `10.0.0.0/24`, `10.0.1.10-10.0.1.80`, `10.0.2.1-50` ou IPs avulsos, separados por vírgula.
2. **Source:**
   - **Zabbix frontend server:** a varredura sai do servidor web, em blocos de 64 IPs, com 2 requisições em paralelo.
   - **Proxy, método Remote command (padrão):** o módulo executa o script global `NetMapper: ping scan` (`script.execute`) no contexto de um host monitorado pelo proxy escolhido, diretamente ou via proxy group. Com isso, o `fping` roda **no proxy**. Só ICMP é testado.
     - **Segurança:** o comando é fixo (`/usr/sbin/fping -a -q -r 1 -t 500 {MANUALINPUT}`). O `{MANUALINPUT}` é validado **pelo Zabbix server** com uma regex que só aceita até 64 IPv4 separados por espaço, o que impede injeção de comandos.
     - **Requisitos:** `EnableRemoteCommands=1` no `zabbix_proxy.conf` (reinicie o proxy), `fping` em `/usr/sbin/fping` no proxy e ao menos um host monitorado pelo proxy visível ao usuário. A role do usuário precisa permitir executar scripts.
     - **Criação do script:** se ele não existir, o módulo mostra a configuração exata. Para Super admins, oferece o botão **Create script**, que o cria com essa configuração.

     | Campo do script (Alerts → Scripts) | Valor |
     |---|---|
     | Name | `NetMapper: ping scan` |
     | Scope / Type / Execute on | Manual host action / Script / Zabbix server (proxy) |
     | Commands | `/usr/sbin/fping -a -q -r 1 -t 500 {MANUALINPUT} 2>/dev/null; exit 0` |
     | Manual input | Enabled, tipo String, regra de validação exibida pelo módulo (`ProxyScript::validator()`) |
     | Timeout | 30s |

   - **Proxy, método Temporary discovery rule:** o módulo cria pela API uma **regra de descoberta temporária** no proxy (`NetMapper temporary scan <userid> <data>`), lê os resultados a cada 10 s e apaga a regra ao terminar. Regras esquecidas (por exemplo, navegador fechado no meio do scan) são apagadas automaticamente após 2 h, na próxima abertura do módulo.
     - Identificar e Localizar vizinhos continuam saindo do **servidor do frontend**, que precisa alcançar os IPs (SNMP/HTTP).
     - Se houver **ações de descoberta** sem condição de regra (por exemplo, "Auto discovery"), elas podem reagir à regra temporária. Revise as ações ou acrescente a condição *Discovery rule ≠ NetMapper…*.
3. **Probes:** ICMP, TCP (perfil mínimo ou padrão IT/OT) e SNMP.
4. **SNMP:** communities em lista, testadas em ordem. Marque **Remember communities** para guardá-las no perfil do seu usuário (tabela `profiles`). Desmarque para apagá-las.
5. Clique num equipamento para ver detalhes e as ações:
   - **Identify:** coleta detalhada (HTTP/HTTPS, banners, SNMP, EtherNet/IP).
   - **Find neighbors (SNMP):** LLDP-MIB, CDP, BRIDGE/Q-BRIDGE-MIB e ARP. O switch é marcado como explorado e os vizinhos novos aparecem ao redor dele.
   - **Neighbors from CLI output:** para equipamentos sem SNMP. Veja a seção sobre CLI.
   - **Add host:** cria o host no Zabbix com IP, grupos, templates (sugeridos pelo fabricante) e interface Agent/SNMP. A community vai como macro `{$SNMP_COMMUNITY}` (ou `{$SNMPV3_*}`), e não em texto puro.
6. **Find neighbors of all switches** percorre em largura todos os switches ainda não explorados, inclusive os descobertos via LLDP. Use **Stop** para interromper.
7. **Save as Zabbix map** cria um mapa nativo (Monitoring → Maps), com hosts como elementos de host e links rotulados com as interfaces.

O mapa (sem nenhuma credencial) fica guardado no `localStorage` do navegador, por usuário, e é restaurado ao reabrir a página. **Export/Import JSON** permite levar o mapa para outro navegador ou guardá-lo como documentação.

## CLI: sem login automático

O módulo **nunca se conecta à CLI dos equipamentos** e **não recebe, guarda nem transmite usuário/senha de CLI**. Em **Neighbors from CLI output**:

1. Escolha o fabricante. A tela lista os comandos de leitura recomendados, para modo **não privilegiado**. Clique num comando para copiá-lo.
2. Faça login você mesmo no equipamento, com uma conta somente leitura, rode os comandos e cole a saída nos campos (Version, LLDP, CDP, MAC table, ARP).
3. O texto é interpretado em memória no servidor e descartado. O resultado entra no mapa exatamente como a coleta via SNMP.

Todos os comandos sugeridos passam por uma verificação (`VendorProfiles::isReadOnly`) que só aceita `show`/`display`, o `print` do RouterOS, o `| no-more` final do Junos e comandos de sessão para desligar a paginação (`terminal length 0`, `cli numlines 0`, `screen-length … temporary/disable`). São rejeitados `configure`, `write`, `copy`, `delete`, `reload`, `set`, `add`, `clear`, `enable` e redirecionamentos.

| Perfil | LLDP | Tabela MAC |
|---|---|---|
| Cisco IOS/IOS-XE/NX-OS, **Rockwell Stratix** | `show lldp neighbors detail` (+ `show cdp neighbors detail`) | `show mac address-table` |
| MikroTik RouterOS (usuário do grupo *read*) | `/ip neighbor print detail without-paging` | `/interface bridge host print detail without-paging` |
| Hirschmann HiOS/Classic | `show lldp remote-data` | `show mac-addr-table` |
| Siemens SCALANCE X/XM/XR | `show lldp neighbors detail` | `show mac-address-table` |
| Siemens RUGGEDCOM ROS/ROX | `show lldp neighbors` | `show mac-address-table` |
| Moxa EDS/IKS/PT | `show lldp entry` | `show mac-address-table` |
| Phoenix Contact, Westermo, Huawei, HPE Comware, Aruba, Juniper, genérico | veja `includes/VendorProfiles.php` | |

> A sintaxe varia com o firmware. Os perfis listam alternativas. Os de Cisco, MikroTik, Hirschmann e Huawei estão cobertos por testes com amostras de saída. Os demais vieram do conhecimento geral desses equipamentos e **devem ser validados** em campo. Para ajustar, edite `includes/VendorProfiles.php`: o parser é genérico e reconhece blocos chave/valor (`Chave: valor`, `Chave ..... valor`, `chave=valor`) e tabelas com cabeçalho.

## Segurança

- **Somente leitura com os equipamentos:**
  - SNMP só usa GET, GETNEXT e GETBULK. O codificador recusa qualquer outra PDU.
  - HTTP é um GET anônimo em `/`.
  - Banners são lidos sem autenticação (no Telnet, todas as opções são recusadas).
  - O EtherNet/IP só envia ListIdentity.
  - O TCP connect fecha a conexão com RST, sem enviar dados.
- **Credenciais:**
  - CLI: nenhuma credencial existe no módulo.
  - SNMPv3: os segredos ficam só no formulário da página. São enviados a cada requisição, nunca gravados (nem no `localStorage`, nem no JSON exportado) e **nunca vão para regras de descoberta**: com SNMPv3, o scan via proxy usa apenas ICMP/TCP.
  - Communities v1/v2c: só persistem se você marcar *Remember communities* (perfil do usuário). Elas são gravadas na regra temporária do proxy enquanto ela existir.
- **CSRF:** todas as actions AJAX são POST com token por action (`CCsrfTokenHelper`), conforme o Zabbix 7.0.
- **Permissões:** as actions exigem usuário Admin ou Super admin. Criação de host e de mapa respeita as permissões da API do usuário.
- **Impacto em OT:** concorrência e timeouts conservadores, com pausa entre pacotes SNMP. Em redes com CLPs antigos, use o perfil **Minimal** de portas, ou só ICMP/SNMP, e prefira janelas de manutenção.

## Configuração (seção `config` do manifest)

Os valores são gravados no banco quando o módulo é registrado e podem ser alterados via API (`module.update`).

| Chave | Padrão | Descrição |
|---|---|---|
| `max_targets` | 4096 | Máximo de IPs por varredura |
| `scan_chunk_size` | 64 | IPs por requisição (source = server) |
| `tcp_timeout_ms` / `tcp_concurrency` | 800 / 64 | TCP connect |
| `snmp_timeout_ms` / `snmp_retries` | 1500 / 1 | SNMP |
| `fping_path` | `/usr/sbin/fping` | Binário do fping |
| `tcp_ports_minimal` / `tcp_ports_standard` | ver manifest | Perfis de portas (inclui 102 S7, 502 Modbus, 44818 EtherNet/IP, 4840 OPC UA, 20000 DNP3) |
| `http_timeout_ms` | 3000 | Identificação HTTP(S) |

## Estrutura

```
manifest.json, Module.php          registro, menu
actions/                           controllers (view + 7 actions JSON)
includes/                          lógica (namespace Modules\NetMapper\Includes)
  Ber, SnmpSession, SnmpV12Session, SnmpV3Session, SnmpProbe   cliente SNMP somente leitura
  Scanner, IpRange, ProxyDiscovery                             varredura server/proxy
  Identifier, Fingerprint, Oui                                 identificação
  NeighborCollector, Topology                                  LLDP/CDP/FDB/ARP, portas de acesso
  VendorProfiles, CliParsers                                   comandos sugeridos, parser da saída colada
  HostLookup, Config, Util, BaseJsonController
views/netmapper.view.php, views/js/netmapper.view.js.php       página e mapa (SVG, sem dependências externas)
assets/css/netmapper.css                                       estilos (escopo .netmapper, temas claro/escuro)
```

## Limitações conhecidas

- Somente IPv4.
- LLDP-V2-MIB (IEEE 802.1AB-2009) não é lido, apenas LLDP-MIB (`1.0.8802.1.1.2`). A maioria dos equipamentos expõe as duas.
- A tabela MAC de alguns equipamentos MikroTik não aparece via SNMP. Nesses casos, use a CLI (colar saída).
- Pelo proxy, a identificação detalhada e os vizinhos continuam saindo do servidor do frontend.
- A tabela de OUIs (`Oui.php`) é pequena e serve só como dica.
