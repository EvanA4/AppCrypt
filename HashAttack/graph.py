import os
import matplotlib.pyplot as plt
import numpy as np
import math


BIT_SIZES = range(8, 24, 2)
FILE_PATH = os.path.dirname(os.path.realpath(__file__))
CACHE_PATH = os.path.join(FILE_PATH, "cache")

# slope, y-offset
ECI_PARAMS = [math.log(2) / 2, math.log(math.pi / 2) / 2]
EPI_PARAMS = [math.log(2), 0]
ECI_LOGS = [ECI_PARAMS[0]*bit_size + ECI_PARAMS[1] for bit_size in BIT_SIZES]
EPI_LOGS = [EPI_PARAMS[0]*bit_size + EPI_PARAMS[1] for bit_size in BIT_SIZES]
ECI_VALS = np.exp(ECI_LOGS)
EPI_VALS = np.exp(EPI_LOGS)
ECI_STR = f"{math.exp(ECI_PARAMS[1]):.3f}e^({ECI_PARAMS[0]:.3f}x)"
EPI_STR = f"{math.exp(EPI_PARAMS[1]):.3f}e^({EPI_PARAMS[0]:.3f}x)"


def verify_context():
    if not os.path.exists(CACHE_PATH):
        print("Must run graph.py after main.py")
        exit(-1)

    csvs = set([os.path.join(CACHE_PATH, entry) for entry in os.listdir(CACHE_PATH)])

    for bit_size in BIT_SIZES:
        cache_file_path = os.path.join(CACHE_PATH, f"{bit_size}-bit.csv")
        if cache_file_path not in csvs:
            print("Must run graph.py after main.py")
            exit(-1)


def load_data():
    all_preimage_vals = []
    all_collision_vals = []

    for bit_size in BIT_SIZES:
        cache_file_path = os.path.join(CACHE_PATH, f"{bit_size}-bit.csv")
        cache_file = open(cache_file_path, "r")

        bit_preimage_vals = []
        bit_collision_vals = []
        lines = cache_file.readlines()
        for line in lines[1:]:
            raw_values = line.strip().split(",")
            value = int(raw_values[3])
            if "PREIMAGE" in line: bit_preimage_vals.append(value)
            else: bit_collision_vals.append(value)
            
        all_preimage_vals.append(bit_preimage_vals)
        all_collision_vals.append(bit_collision_vals)

    return (all_preimage_vals, all_collision_vals)


def make_graph(data, attack_type):
    data_means = [np.mean(x) for x in data]
    best_fit = np.polyfit(BIT_SIZES, np.log(data_means), 1)
    best_slope = best_fit[0]
    best_base = np.exp(best_fit[1])
    preds = [best_base*np.exp(best_slope*bit_size) for bit_size in BIT_SIZES]
    best_str = f"{best_base:.3f}e^({best_slope:.3f}x)"

    fake_x = [i+1 for i in range(len(data))]

    plt.figure(figsize=(10, 6))
    plt.title(f"{attack_type} Attack Iterations vs. Hash Size")
    plt.xlabel("Hash Size (bits)")
    plt.ylabel(f"{attack_type} Attack Iterations")
    plt.yscale('log')
    plt.boxplot(data)
    plt.xticks(fake_x, BIT_SIZES)
    plt.plot(fake_x, data_means, label="Mean Iterations", c='c')
    plt.plot(fake_x, preds, label=f"Best-Fit {best_str}", c='m')
    expected_vals = ECI_VALS if attack_type == "Collision" else EPI_VALS
    expected_str = ECI_STR if attack_type == "Collision" else EPI_STR
    plt.plot(fake_x, expected_vals, label=f"Expected Iterations {expected_str}", c='r')
    plt.legend()
    plt.savefig(f"{attack_type.lower()}.png", dpi=300)


def main():
    verify_context()
    preimage_vals, collision_vals = load_data()
    make_graph(preimage_vals, "Preimage")
    make_graph(collision_vals, "Collision")


if __name__ == "__main__":
    main()