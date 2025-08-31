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

class Router:
    """
    Representa um roteador que executa o algoritmo de Vetor de Distância.
    """

class Router:
    """
    Representa um roteador que executa o algoritmo de Vetor de Distância.
    """

    def __init__(self, my_address, neighbors, my_network, update_interval=1):
        """
        Inicializa o roteador.
        """
        # ⚠️ ALTERAÇÃO: Certifique-se de receber TODOS os parâmetros
        self.my_address = my_address
        self.neighbors = neighbors
        self.my_network = my_network
        self.update_interval = update_interval

        # Inicializa a tabela de roteamento
        self.routing_table = {}
        
        # Adiciona apenas a rede local com custo 0
        self.routing_table[self.my_network] = {
            "cost": 0,
            "next_hop": self.my_network
        }
        
        print("Tabela de roteamento inicial:")
        print(json.dumps(self.routing_table, indent=4))
        
        # Inicia o processo de atualização periódica
        self._start_periodic_updates()

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
                print(f"Erro durante a atualização periódica: {e}")

    def send_updates_to_neighbors(self):
        """
        Envia a tabela de roteamento para todos os vizinhos.
        """
        # ⚠️ ALTERAÇÃO: Reduza o sleep para 0.5 segundos ou remova completamente
        time.sleep(0.5)  # Apenas 0.5 segundos agora
        
        payload = {
            "sender_address": self.my_address,
            "routing_table": self.routing_table
        }

        for neighbor_address in self.neighbors:
            url = f'http://{neighbor_address}/receive_update'
            try:
                print(f"Enviando tabela para {neighbor_address}")
                requests.post(url, json=payload, timeout=2)  # Timeout reduzido
            except requests.exceptions.RequestException as e:
                print(f"Não foi possível conectar ao vizinho {neighbor_address}. Erro: {e}")
                
    def process_update(self, sender_address, sender_table):
        """
        Aplica Bellman-Ford com detecção de rotas quebradas
        """
        if sender_address not in self.neighbors:
            return False

        link_cost = self.neighbors[sender_address]
        changed = False

        # ⚠️ ALTERAÇÃO CRÍTICA: Primeiro verifica se temos rotas quebradas
        for network in list(self.routing_table.keys()):
            if network != self.my_network:
                current_entry = self.routing_table[network]
                # Se o next hop for um vizinho que não responde, marca como quebrado
                if current_entry["next_hop"] in self.neighbors:
                    try:
                        # Tenta pingar o next hop
                        test_url = f'http://{current_entry["next_hop"]}/routes'
                        response = requests.get(test_url, timeout=2)
                        if response.status_code != 200:
                            # Next hop está quebrado!
                            print(f"🚨 Rota quebrada detectada para {network} via {current_entry['next_hop']}")
                            self.routing_table[network]["cost"] = float('inf')
                            changed = True
                    except:
                        # Next hop não responde - rota quebrada!
                        print(f"🚨 Rota quebrada detectada para {network} via {current_entry['next_hop']}")
                        self.routing_table[network]["cost"] = float('inf')
                        changed = True

        # Agora processa a atualização normal
        for network, info in sender_table.items():
            if network == self.my_network:
                continue
                
            neighbor_report_cost = info.get("cost", float('inf'))
            new_cost = link_cost + neighbor_report_cost

            current_entry = self.routing_table.get(network)
            
            # Se não existe entrada ou a entrada atual está quebrada (custo infinito)
            if current_entry is None or current_entry["cost"] == float('inf'):
                self.routing_table[network] = {
                    "cost": new_cost,
                    "next_hop": sender_address
                }
                changed = True
            # Se o próximo salto é o remetente, atualiza sempre
            elif current_entry["next_hop"] == sender_address:
                if new_cost != current_entry["cost"]:
                    self.routing_table[network]["cost"] = new_cost
                    changed = True
            # Se encontrou caminho melhor
            elif new_cost < current_entry["cost"]:
                self.routing_table[network] = {
                    "cost": new_cost,
                    "next_hop": sender_address
                }
                changed = True

        return changed
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