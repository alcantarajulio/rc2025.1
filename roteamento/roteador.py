# -*- coding: utf-8 -*-

import csv
import json
import threading
import time
from argparse import ArgumentParser

import requests
from flask import Flask, jsonify, request


class Router:
    """
    Representa um roteador que executa o algoritmo de Vetor de Distância.
    """

    def __init__(self, my_address, neighbors, my_network, update_interval=1):
        """
        Inicializa o roteador.

        :param my_address: O endereço (ip:porta) deste roteador.
        :param neighbors: Um dicionário contendo os vizinhos diretos e o custo do link.
                          Ex: {'127.0.0.1:5001': 5, '127.0.0.1:5002': 10}
        :param my_network: A rede que este roteador administra diretamente.
                           Ex: '10.0.1.0/24'
        :param update_interval: O intervalo em segundos para enviar atualizações, o tempo que o roteador espera
                                antes de enviar atualizações para os vizinhos.
        """
        self.my_address = my_address
        self.neighbors = neighbors
        self.my_network = my_network
        self.update_interval = update_interval

        # TODO: Este é o local para criar e inicializar sua tabela de roteamento.
        #
        # 1. Crie a estrutura de dados para a tabela de roteamento. Um dicionário é
        #    uma ótima escolha, onde as chaves são as redes de destino (ex: '10.0.1.0/24')
        #    e os valores são outro dicionário contendo 'cost' e 'next_hop'.
        #    Ex: {'10.0.1.0/24': {'cost': 0, 'next_hop': '10.0.1.0/24'}}
        #
        # 2. Adicione a rota para a rede que este roteador administra diretamente
        #    (a rede em 'self.my_network'). O custo para uma rede diretamente
        #    conectada é 0, e o 'next_hop' pode ser a própria rede ou o endereço do roteador.
        #
        # 3. Adicione as rotas para seus vizinhos diretos, usando o dicionário
        #    'self.neighbors'. Para cada vizinho, o 'cost' é o custo do link direto
        #    e o 'next_hop' é o endereço do próprio vizinho.

        self.routing_table = {}

        self.routing_table[self.my_network] = {"cost": 0, "next_hop": self.my_network}

        for neighbor_addr, link_cost in self.neighbors.items():
            if (
                neighbor_addr not in self.routing_table
                or link_cost < self.routing_table[neighbor_addr]["cost"]
            ):
                self.routing_table[neighbor_addr] = {
                    "cost": link_cost,
                    "next_hop": neighbor_addr,
                }
        print("Tabela de roteamento inicial:")
        print(json.dumps(self.routing_table, indent=4))

        # Inicia o processo de atualização periódica em uma thread separada
        self._start_periodic_updates()

    def process_update(self, sender_address, sender_table) -> bool:
        """
        Aplica Bellman-Ford usando a tabela recebida de um vizinho
        return: True se a tabela mudou
        """
        if sender_address not in self.neighbors:
            print(f"Ignorando update de non-neighbors {sender_address}")
            return False

        link_cost = self.neighbors[sender_address]
        changed = False

        for network, info in sender_table.items():
            neighbor_report_cost = info.get("cost", float("inf"))
            new_cost = link_cost + neighbor_report_cost

            # evita criar rota com destino igual ao próprio endereço (loop)
            if network == self.my_address:
                continue

            current_entry = self.routing_table.get(network)

            if current_entry is None:
                # nova rota
                self.routing_table[network] = {
                    "cost": new_cost,
                    "next_hop": sender_address,
                }
                changed = True
                continue

            current_cost = current_entry["cost"]
            current_next_hop = current_entry["next_hop"]

            if new_cost < current_cost or current_next_hop == sender_address:
                if new_cost != current_cost:
                    self.routing_table[network]["cost"] = new_cost
                    self.routing_table[network]["next_hop"] = sender_address
                    changed = True

        return changed

    def _start_periodic_updates(self):
        """Inicia uma thread para enviar atualizações periodicamente."""
        thread = threading.Thread(target=self._periodic_update_loop)
        thread.daemon = True
        thread.start()

    def _periodic_update_loop(self):
        """Loop que envia atualizações de roteamento em intervalos regulares."""
        while True:
            time.sleep(self.update_interval)
            print(
                f"[{time.ctime()}] Enviando atualizações periódicas para os vizinhos..."
            )
            try:
                self.send_updates_to_neighbors()
            except Exception as e:
                print(f"Erro durante a atualização periódida: {e}")

    def _find_optimal_summarization(self, networks):
        """
        Encontra a sumarização ótima para um conjunto de redes.

        :param networks: Lista de redes no formato 'IP/prefixo'
        :return: (summarized_route, included_networks) ou (None, [])
        """
        if len(networks) < 2:
            return None, []

        # Converte todas as redes para inteiros e extrai prefixos
        network_info = []
        for network in networks:
            if "/" not in network:
                continue
            try:
                ip, prefix = network.split("/")
                prefix_len = int(prefix)
                ip_int = self._ip_to_int(ip)
                if ip_int is not None:
                    network_info.append((ip_int, prefix_len, network))
            except (ValueError, IndexError):
                continue

        if len(network_info) < 2:
            return None, []

        # Agrupa por prefixo (só sumariza redes do mesmo tamanho)
        prefix_groups = {}
        for ip_int, prefix_len, network in network_info:
            if prefix_len not in prefix_groups:
                prefix_groups[prefix_len] = []
            prefix_groups[prefix_len].append((ip_int, network))

        best_summarization = None
        best_included_networks = []

        # Tenta sumarizar cada grupo de prefixo
        for prefix_len, group in prefix_groups.items():
            if len(group) < 2:
                continue

            # Ordena por endereço de rede
            group.sort(key=lambda x: x[0])

            # Encontra o menor e maior endereço de rede
            min_ip = group[0][0]
            max_ip = group[-1][0]

            # Calcula o endereço de rede para cada IP
            network_mask = 0xFFFFFFFF << (32 - prefix_len)
            min_network = min_ip & network_mask
            max_network = max_ip & network_mask

            # Encontra o prefixo ótimo que cubra todas as redes
            optimal_prefix = self._find_covering_prefix(
                min_network, max_network, prefix_len
            )

            if optimal_prefix is not None:
                # Verifica se a sumarização é válida (não inclui redes inexistentes)
                summarized_route = f"{self._int_to_ip(min_network)}/{optimal_prefix}"

                # Conta quantas redes originais estão incluídas
                included_count = 0
                included_networks = []
                for ip_int, network in group:
                    if self._is_network_included(
                        ip_int, prefix_len, min_network, optimal_prefix
                    ):
                        included_count += 1
                        included_networks.append(network)

                # Se a sumarização inclui pelo menos 2 redes, é válida
                if included_count >= 2:
                    if best_summarization is None or optimal_prefix < int(
                        best_summarization.split("/")[1]
                    ):
                        best_summarization = summarized_route
                        best_included_networks = included_networks

        return best_summarization, best_included_networks

    def _ip_to_int(self, ip):
        """Converte IP string para inteiro de 32 bits."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return None
            return (
                (int(parts[0]) << 24)
                + (int(parts[1]) << 16)
                + (int(parts[2]) << 8)
                + int(parts[3])
            )
        except (ValueError, IndexError):
            return None

    def _int_to_ip(self, ip_int):
        """Converte inteiro de 32 bits para IP string."""
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

    def _find_covering_prefix(self, min_network, max_network, original_prefix):
        """
        Encontra o prefixo ótimo que cubra todas as redes.

        :param min_network: Menor endereço de rede
        :param max_network: Maior endereço de rede
        :param original_prefix: Prefixo original das redes
        :return: Prefixo ótimo ou None
        """
        # Começa com o prefixo original e vai diminuindo até encontrar um que cubra tudo
        for prefix in range(original_prefix - 1, 7, -1):  # Limita a /8
            network_size = 2 ** (32 - prefix)
            network_mask = 0xFFFFFFFF << (32 - prefix)

            # Calcula o endereço da super-rede
            super_network = min_network & network_mask

            # Verifica se esta super-rede cobre todas as redes originais
            if (
                super_network <= min_network
                and super_network + network_size > max_network
            ):
                return prefix

        return None

    def _is_network_included(
        self, network_ip, network_prefix, super_network, super_prefix
    ):
        """
        Verifica se uma rede está incluída em uma super-rede.

        :param network_ip: Endereço IP da rede
        :param network_prefix: Prefixo da rede
        :param super_network: Endereço da super-rede
        :param super_prefix: Prefixo da super-rede
        :return: True se a rede está incluída
        """
        network_mask = 0xFFFFFFFF << (32 - network_prefix)
        actual_network = network_ip & network_mask

        super_mask = 0xFFFFFFFF << (32 - super_prefix)
        super_start = super_network & super_mask
        super_end = super_start + (2 ** (32 - super_prefix))

        return super_start <= actual_network < super_end

    def _summarize_routing_table(self, routing_table):
        """
        Aplica sumarização de rotas na tabela de roteamento.

        :param routing_table: Tabela de roteamento original
        :return: Tabela sumarizada
        """
        if not routing_table:
            return routing_table

        # Cria uma cópia da tabela para não modificar a original
        summarized_table = routing_table.copy()

        # Agrupa rotas por next_hop para aplicar sumarização
        routes_by_next_hop = {}
        for network, info in summarized_table.items():
            next_hop = info["next_hop"]
            if next_hop not in routes_by_next_hop:
                routes_by_next_hop[next_hop] = []
            routes_by_next_hop[next_hop].append(network)

        # Aplica sumarização para cada grupo de next_hop
        for next_hop, networks in routes_by_next_hop.items():
            if len(networks) < 2:
                continue

            # Filtra apenas redes válidas (com formato IP/prefixo)
            valid_networks = [net for net in networks if "/" in net]

            if len(valid_networks) < 2:
                continue

            # Encontra TODAS as sumarizações possíveis para este grupo
            all_summarizations = self._find_all_summarizations(valid_networks)

            # Aplica a sumarização mais abrangente (menor prefixo = maior rede)
            if all_summarizations:
                # Escolhe a sumarização com menor prefixo (maior rede)
                best_summarization = min(
                    all_summarizations, key=lambda x: int(x[0].split("/")[1])
                )
                summarized_route, included_networks = best_summarization

                # Calcula o custo da rota sumarizada (maior custo entre as redes incluídas)
                max_cost = max(
                    summarized_table[net]["cost"] for net in included_networks
                )

                # Remove TODAS as rotas originais que estão cobertas pela sumarização
                networks_to_remove = []
                for net in summarized_table:
                    if (
                        net in valid_networks
                        and self._is_network_included_in_summary(
                            net, summarized_route
                        )
                    ):
                        networks_to_remove.append(net)

                for net in networks_to_remove:
                    if net in summarized_table:
                        del summarized_table[net]

                # Adiciona a rota sumarizada
                summarized_table[summarized_route] = {
                    "cost": max_cost,
                    "next_hop": next_hop,
                }

                print(f"Sumarização aplicada para {next_hop}:")
                print(f"  Redes originais: {included_networks}")
                print(f"  Rede sumarizada: {summarized_route} (custo: {max_cost})")

        return summarized_table

    def _find_all_summarizations(self, networks):
        """
        Encontra todas as sumarizações possíveis para um conjunto de redes.

        :param networks: Lista de redes no formato 'IP/prefixo'
        :return: Lista de tuplas (summarized_route, included_networks)
        """
        if len(networks) < 2:
            return []

        # Converte todas as redes para inteiros e extrai prefixos
        network_info = []
        for network in networks:
            if "/" not in network:
                continue
            try:
                ip, prefix = network.split("/")
                prefix_len = int(prefix)
                ip_int = self._ip_to_int(ip)
                if ip_int is not None:
                    network_info.append((ip_int, prefix_len, network))
            except (ValueError, IndexError):
                continue

        if len(network_info) < 2:
            return []

        # Agrupa por prefixo (só sumariza redes do mesmo tamanho)
        prefix_groups = {}
        for ip_int, prefix_len, network in network_info:
            if prefix_len not in prefix_groups:
                prefix_groups[prefix_len] = []
            prefix_groups[prefix_len].append((ip_int, network))

        all_summarizations = []

        # Tenta sumarizar cada grupo de prefixo
        for prefix_len, group in prefix_groups.items():
            if len(group) < 2:
                continue

            # Ordena por endereço de rede
            group.sort(key=lambda x: x[0])

            # Encontra o menor e maior endereço de rede
            min_ip = group[0][0]
            max_ip = group[-1][0]

            # Calcula o endereço de rede para cada IP
            network_mask = 0xFFFFFFFF << (32 - prefix_len)
            min_network = min_ip & network_mask
            max_network = max_ip & network_mask

            # Encontra o prefixo ótimo que cubra todas as redes
            optimal_prefix = self._find_covering_prefix(
                min_network, max_network, prefix_len
            )

            if optimal_prefix is not None:
                # Verifica se a sumarização é válida
                summarized_route = f"{self._int_to_ip(min_network)}/{optimal_prefix}"

                # Conta quantas redes originais estão incluídas
                included_count = 0
                included_networks = []
                for ip_int, network in group:
                    if self._is_network_included(
                        ip_int, prefix_len, min_network, optimal_prefix
                    ):
                        included_count += 1
                        included_networks.append(network)

                # Se a sumarização inclui pelo menos 2 redes, é válida
                if included_count >= 2:
                    all_summarizations.append((summarized_route, included_networks))

        return all_summarizations

    def _is_network_included_in_summary(self, network, summarized_route):
        """
        Verifica se uma rede está incluída em uma rota sumarizada.

        :param network: Rede a verificar (ex: '10.0.1.0/24')
        :param summarized_route: Rota sumarizada (ex: '10.0.0.0/22')
        :return: True se a rede está incluída
        """
        if "/" not in network or "/" not in summarized_route:
            return False

        try:
            # Extrai informações da rede
            net_ip, net_prefix = network.split("/")
            net_ip_int = self._ip_to_int(net_ip)
            net_prefix_len = int(net_prefix)

            # Extrai informações da rota sumarizada
            sum_ip, sum_prefix = summarized_route.split("/")
            sum_ip_int = self._ip_to_int(sum_ip)
            sum_prefix_len = int(sum_prefix)

            if net_ip_int is None or sum_ip_int is None:
                return False

            # Calcula endereços de rede
            net_mask = 0xFFFFFFFF << (32 - net_prefix_len)
            net_addr = net_ip_int & net_mask

            sum_mask = 0xFFFFFFFF << (32 - sum_prefix_len)
            sum_addr = sum_ip_int & sum_mask
            sum_size = 2 ** (32 - sum_prefix_len)

            # Verifica se a rede está incluída na sumarização
            return sum_addr <= net_addr < sum_addr + sum_size

        except (ValueError, IndexError):
            return False

    def send_updates_to_neighbors(self):
        """
        Envia a tabela de roteamento (potencialmente sumarizada) para todos os vizinhos.
        """
        # Cria uma cópia da tabela de roteamento para aplicar sumarização
        tabela_para_enviar = self.routing_table.copy()

        # Aplica a lógica de sumarização na cópia
        tabela_sumarizada = self._summarize_routing_table(tabela_para_enviar)

        print("Tabela original:")
        print(json.dumps(self.routing_table, indent=4))
        print("Tabela sumarizada para envio:")
        print(json.dumps(tabela_sumarizada, indent=4))

        payload = {
            "sender_address": self.my_address,
            "routing_table": tabela_sumarizada,
        }

        for neighbor_address in self.neighbors:
            url = f"http://{neighbor_address}/receive_update"
            try:
                print(f"Enviando tabela sumarizada para {neighbor_address}")
                requests.post(url, json=payload, timeout=5)
            except requests.exceptions.RequestException as e:
                print(
                    f"Não foi possível conectar ao vizinho {neighbor_address}. Erro: {e}"
                )


# --- API Endpoints ---
# Instância do Flask e do Roteador (serão inicializadas no main)
app = Flask(__name__)
router_instance = None


@app.route("/routes", methods=["GET"])
def get_routes():
    """Endpoint para visualizar a tabela de roteamento atual."""
    if router_instance:
        return jsonify(
            {
                "message": "Tabela de roteamento atual",
                "vizinhos": router_instance.neighbors,
                "my_network": router_instance.my_network,
                "my_address": router_instance.my_address,
                "update_interval": router_instance.update_interval,
                "routing_table": router_instance.routing_table,  # Exibe a tabela de roteamento atual
            }
        )
    return jsonify({"error": "Roteador não inicializado"}), 500


@app.route("/receive_update", methods=["POST"])
def receive_update():
    """Endpoint que recebe atualizações de roteamento de um vizinho."""
    if not request.json:
        return jsonify({"error": "Invalid request"}), 400

    data = request.json
    sender_address = data.get("sender_address")
    sender_table = data.get("routing_table")

    if not sender_address or not isinstance(sender_table, dict):
        return jsonify({"error": "Missing sender_address or routing_table"}), 400

    print(f"Recebida atualização de {sender_address}:")
    print(json.dumps(sender_table, indent=4))

    changed = router_instance.process_update(sender_address, sender_table)

    if changed:
        print("Tabela atualizada:")
        print(json.dumps(router_instance.routing_table, indent=4))

    return jsonify({"status": "ok", "changed": changed}), 200


if __name__ == "__main__":
    parser = ArgumentParser(description="Simulador de Roteador com Vetor de Distância")
    parser.add_argument(
        "-p", "--port", type=int, default=5000, help="Porta para executar o roteador."
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        required=True,
        help="Arquivo CSV de configuração de vizinhos.",
    )
    parser.add_argument(
        "--network",
        type=str,
        required=True,
        help="Rede administrada por este roteador (ex: 10.0.1.0/24).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Intervalo de atualização periódica em segundos.",
    )
    args = parser.parse_args()

    # Leitura do arquivo de configuração de vizinhos
    neighbors_config = {}
    try:
        with open(args.file, mode="r") as infile:
            reader = csv.DictReader(infile)
            for row in reader:
                neighbors_config[row["vizinho"]] = int(row["custo"])
    except FileNotFoundError:
        print(f"Erro: Arquivo de configuração '{args.file}' não encontrado.")
        exit(1)
    except (KeyError, ValueError) as e:
        print(
            f"Erro no formato do arquivo CSV: {e}. Verifique as colunas 'vizinho' e 'custo'."
        )
        exit(1)

    my_full_address = f"127.0.0.1:{args.port}"
    print("--- Iniciando Roteador ---")
    print(f"Endereço: {my_full_address}")
    print(f"Rede Local: {args.network}")
    print(f"Vizinhos Diretos: {neighbors_config}")
    print(f"Intervalo de Atualização: {args.interval}s")
    print("--------------------------")

    router_instance = Router(
        my_address=my_full_address,
        neighbors=neighbors_config,
        my_network=args.network,
        update_interval=args.interval,
    )

    # Inicia o servidor Flask
    app.run(host="0.0.0.0", port=args.port, debug=False)
