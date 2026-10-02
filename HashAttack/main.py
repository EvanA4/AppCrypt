import os
import hashlib
import secrets
import string


RANDOM_STRING_SIZE = 64


def random_alphanumeric() -> str:
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(RANDOM_STRING_SIZE))


def get_bits(data: bytes, n: int) -> bytes:
    if n == 0: return b""

    byte_count = (n + 7) // 8
    result = bytearray(data[:byte_count])

    remaining_bits = n % 8
    if remaining_bits:
        result[-1] &= (0xFF << (8 - remaining_bits)) & 0xFF

    return bytes(result)


def hash_sha1(message, num_bits):
    hash_fn = hashlib.sha1(usedforsecurity=True)
    hash_fn.update(message.encode())
    return get_bits(hash_fn.digest(), num_bits)


def preimage_attack(num_bits):
    target_msg = random_alphanumeric()
    target = hash_sha1(target_msg, num_bits)

    ctr = 0
    while True:
        ctr += 1
        candidate_msg = random_alphanumeric()
        candidate = hash_sha1(candidate_msg, num_bits)
        if candidate == target: break

    return ctr

def collision_attack(num_bits):
    seen = set()

    ctr = 0
    while True:
        ctr += 1
        candidate_msg = random_alphanumeric()
        candidate = hash_sha1(candidate_msg, num_bits)
        if candidate in seen: break
        else: seen.add(candidate)

    return ctr

# bit size, trial number, attack type, value

def main():
    file_path = os.path.dirname(os.path.realpath(__file__))
    cache_path = os.path.join(file_path, "cache")
    if not os.path.exists(cache_path):
        os.mkdir(cache_path)

    bit_sizes = range(8, 24, 2)
    for bit_size in bit_sizes:
        # check if can skip
        cache_file_path = os.path.join(cache_path, f"{bit_size}-bit.csv")
        if os.path.exists(cache_file_path):
            temp_file = open(cache_file_path, "r")
            lines = temp_file.readlines()
            temp_file.close()
            if len(lines) == 101:
                print(f"Skipping {bit_size}...")
                continue

        # no file in cache, do work
        cache_file = open(cache_file_path, "w")
        cache_file.write("bit size, trial number, attack type, value\n")
        for trial_num in range(50):
            print(f"{bit_size}: {trial_num * 2}%", end="\r")
            preimage_num = preimage_attack(bit_size)
            collision_num = collision_attack(bit_size)
            cache_file.write(f"{bit_size},{trial_num},PREIMAGE,{preimage_num}\n")
            cache_file.write(f"{bit_size},{trial_num},COLLISION,{collision_num}\n")
        print(f"{bit_size}: 100%")
        
        cache_file.close()


if __name__ == "__main__":
    main()