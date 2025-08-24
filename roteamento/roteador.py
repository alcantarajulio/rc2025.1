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
                                antes de enviar atualizações para os vizinhos.        """
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

        self.routing_table[self.my_network] = {
            "cost": 0,
            "next_hop": self.my_address
        }

        for neighbor_addr, link_cost in self.neighbors.items():
            if neighbor_addr not in self.routing_table or link_cost < self.routing_table[neighbor_addr]['cost']:
                self.routing_table[neighbor_addr] = {
                    "cost": link_cost,
                    "next_hop": neighbor_addr
                }
        print("Tabela de roteamento inicial:")
        print(json.dumps(self.routing_table, indent=4))

        # Inicia o processo de atualização periódica em uma thread separada
        self._start_periodic_updates()

    def process_update(self, sender_address, sender_table):
        """
        Aplica Bellman-Ford usando a tabela recebida de um vizinho 
        return: true se a tabela mudou
        """
        if sender_address not in self.neighbors:
            print(f"Ignorando update de non-neighbors {sender_address}")
            return False

        link_cost = self.neighbors[sender_address]
        changed = False

        for network, info in sender_table.items():
            neighbor_report_cost = info.get("cost", float('inf'))
            new_cost = link_cost + neighbor_report_cost

            # evita criar rota com destino igual ao próprio endereço (loop)
            if network == self.my_address:
                continue

            current_entry = self.routing_table.get(network)

            if current_entry is None:
                # nova rota
                self.routing_table[network] = {
                    "cost": new_cost,
                    "next_hop": sender_address
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
            print(f"[{time.ctime()}] Enviando atualizações periódicas para os vizinhos...")
            try:
                self.send_updates_to_neighbors()
            except Exception as e:
                print(f"Erro durante a atualização periódida: {e}")

    def send_updates_to_neighbors(self):
        """
        Envia a tabela de roteamento (potencialmente sumarizada) para todos os vizinhos.
        """
        # TODO: O código abaixo envia a tabela de roteamento *diretamente*.
        #
        # ESTE TRECHO DEVE SER CHAMAADO APOS A SUMARIZAÇÃO.
        #
        # dica:
        # 1. CRIE UMA CÓPIA da `self.routing_table` NÃO ALTERE ESTA VALOR.
        # 2. IMPLEMENTE A LÓGICA DE SUMARIZAÇÃO nesta cópia.
        # 3. ENVIE A CÓPIA SUMARIZADA no payload, em vez da tabela original.
        
        tabela_para_enviar = self.routing_table # ATENÇÃO: Substitua pela cópia sumarizada.

        payload = {
            "sender_address": self.my_address,
            "routing_table": tabela_para_enviar
        }

        for neighbor_address in self.neighbors:
            url = f'http://{neighbor_address}/receive_update'
            try:
                print(f"Enviando tabela para {neighbor_address}")
                requests.post(url, json=payload, timeout=5)
            except requests.exceptions.RequestException as e:
                print(f"Não foi possível conectar ao vizinho {neighbor_address}. Erro: {e}")

# --- API Endpoints ---
# Instância do Flask e do Roteador (serão inicializadas no main)
app = Flask(__name__)
router_instance = None

@app.route('/routes', methods=['GET'])
def get_routes():
    """Endpoint para visualizar a tabela de roteamento atual."""
    # TODO: Aluno! Este endpoint está parcialmente implementado para ajudar na depuração.
    # Você pode mantê-lo como está ou customizá-lo se desejar.
    # - mantenha o routing_table como parte da resposta JSON.
    if router_instance:
        return jsonify({
            "message": "Não implementado!.",
            "vizinhos" : router_instance.neighbors,
            "my_network": router_instance.my_network,
            "my_address": router_instance.my_address,
            "update_interval": router_instance.update_interval,
            "routing_table": router_instance.routing_table # Exibe a tabela de roteamento atual (a ser implementada)
        })
    return jsonify({"error": "Roteador não inicializado"}), 500

@app.route('/receive_update', methods=['POST'])
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

if __name__ == '__main__':
    parser = ArgumentParser(description="Simulador de Roteador com Vetor de Distância")
    parser.add_argument('-p', '--port', type=int, default=5000, help="Porta para executar o roteador.")
    parser.add_argument('-f', '--file', type=str, required=True, help="Arquivo CSV de configuração de vizinhos.")
    parser.add_argument('--network', type=str, required=True, help="Rede administrada por este roteador (ex: 10.0.1.0/24).")
    parser.add_argument('--interval', type=int, default=10, help="Intervalo de atualização periódica em segundos.")
    args = parser.parse_args()

    # Leitura do arquivo de configuração de vizinhos
    neighbors_config = {}
    try:
        with open(args.file, mode='r') as infile:
            reader = csv.DictReader(infile)
            for row in reader:
                neighbors_config[row['vizinho']] = int(row['custo'])
    except FileNotFoundError:
        print(f"Erro: Arquivo de configuração '{args.file}' não encontrado.")
        exit(1)
    except (KeyError, ValueError) as e:
        print(f"Erro no formato do arquivo CSV: {e}. Verifique as colunas 'vizinho' e 'custo'.")
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
        update_interval=args.interval
    )

    # Inicia o servidor Flask
    app.run(host='0.0.0.0', port=args.port, debug=False)