import os

neighbors = {
    1:  [(12, 1), (2, 50)],
    2:  [(1, 1), (3, 3)],
    3:  [(2, 2), (4, 1)],
    4:  [(3, 3), (5, 4)],
    5:  [(4, 1), (6, 1)],
    6:  [(5, 14), (7, 1)],
    7:  [(6, 1), (8, 15)],
    8:  [(7, 1), (9, 3)],
    9:  [(8, 2), (10, 1)],
    10: [(9, 5), (11, 1)],
    11: [(10, 10), (12, 1)],
    12: [(11, 2), (1, 1)],
}

output_dir = "."
os.makedirs(output_dir, exist_ok=True)

for i in range(1, 13):
    filename = f"{output_dir}/R{i}.csv"
    with open(filename, "w") as f:
        f.write("vizinho,custo\n")
        for neighbor_idx, cost in neighbors[i]:
            neighbor_ip = f"127.0.0.1:50{(str(neighbor_idx)).rjust(2, '0')}"
            f.write(f"{neighbor_ip},{cost}\n")
print("Arquivos gerados")