import os
import matplotlib.pyplot as plt
import numpy as np


BIT_SIZES = range(8, 24, 2)
FILE_PATH = os.path.dirname(os.path.realpath(__file__))
CACHE_PATH = os.path.join(FILE_PATH, "cache")


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


def main():
    verify_context()
    preimage_vals, collision_vals = load_data()
    
    preimage_means = [np.mean(x) for x in preimage_vals]
    best_fit = np.polyfit(BIT_SIZES, np.log(preimage_means), 1)
    best_slope = best_fit[0]
    best_base = np.exp(best_fit[1])
    preds = [best_base*np.exp(best_slope*bit_size) for bit_size in BIT_SIZES]
    best_str = f"{best_base:.3f}e^({best_slope:.3f}x)"

    fake_x = [i+1 for i in range(len(preimage_vals))]

    plt.figure(figsize=(10, 6))
    plt.title("Hash Size vs. Preimage Attack Iterations")
    plt.xlabel("Hash Size (bits)")
    plt.ylabel("Preimage Attack Iterations")
    plt.yscale('log')
    plt.boxplot(preimage_vals)
    plt.xticks(fake_x, BIT_SIZES)
    plt.plot(fake_x, preimage_means, label="Actual")
    plt.plot(fake_x, preds, label=f"Prediction {best_str}")
    plt.legend()
    plt.show()


if __name__ == "__main__":
    main()