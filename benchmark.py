import subprocess
import json
import os
import statistics
import time
from tqdm import tqdm
import matplotlib.pyplot as plt

openssl_path = "/opt/openssl-3.3.2/bin/openssl"
provider_path = "/opt/openssl-3.3.2/lib64/ossl-modules"
tmp = "./tmp"

debug = {
    "keygen": False,
    "commands": False,
}


def cleanup_files(files: list | str):
    if files == "*":
        if os.path.exists(tmp) and (os.listdir(tmp) != []):
            print(" > Residual files found in 'tmp'. Cleaning up...")
            for file in os.listdir(tmp):
                os.remove(f"{tmp}/{file}")

    elif type(files) == list:
        for file in files:
            if os.path.exists(file):
                os.remove(f"{tmp}/{file}")
    else:
        print("Error: cleanup_files() called with unsupported argument.")


def generate_key(algorithm: str) -> bool:
    try:
        print(" > Generating the keys...") if debug["keygen"] else None

        result = subprocess.run([
            openssl_path, 'genpkey',
            '-provider', 'default',
            '-provider', 'oqsprovider',
            '-provider-path', provider_path,
            '-out', f'{tmp}/private_key.pem',
            '-algorithm', algorithm
        ], capture_output=True, text=True, check=True)

        print(f"\nCOMMAND: {' '.join(result.args)}") if debug["commands"] else None
        print("   Private key generated.") if debug["keygen"] else None

        result = subprocess.run([
            openssl_path, 'pkey',
            '-in', f'{tmp}/private_key.pem',
            '-pubout',
            '-out', f'{tmp}/public_key.pem',
            '-provider', 'oqsprovider',
            '-provider', 'default',
            '-provider-path', provider_path
        ], check=True)

        print(f"\nCOMMAND: {' '.join(result.args)}") if debug["commands"] else None
        print("   Public key generated.") if debug["keygen"] else None
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error in key generation for {algorithm.upper()}: ")
        print(f"Command: {' '.join(e.cmd)}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return False


def kem_benchmark(algorithm: str, num_iterations: int = 100) -> dict:
    print(" > Starting KEM benchmark...")
    key_times = []
    encap_times = []
    decap_times = []

    for _ in tqdm(range(num_iterations), desc=f"Benchmark {algorithm}", unit="iter"):
        # Key generation
        start = time.time()
        generate_key(algorithm)
        key_times.append(time.time() - start)

        # Encapsulation
        start = time.time()
        result = subprocess.run([
            openssl_path, "pkeyutl", "-encrypt", "-inkey", f"{tmp}/public_key.pem", "-keyform", "PEM"],
            shell=True, capture_output=True)
        encap_times.append(time.time() - start)
        print(f"\nCOMMAND: {' '.join(result.args)}") if debug["commands"] else None

        # Decapsulation
        start = time.time()
        result = subprocess.run([
            openssl_path, "pkeyutl", "-decrypt", "-inkey", f"{tmp}/private_key.pem", "-keyform", "PEM"],
            shell=True, capture_output=True)
        decap_times.append(time.time() - start)
        print(f"\nCOMMAND: {' '.join(result.args)}") if debug["commands"] else None

        cleanup_files(["private_key.pem", "public_key.pem"])

    return {
        'key_generation_avg': statistics.mean(key_times),
        'encapsulation_avg': statistics.mean(encap_times),
        'decapsulation_avg': statistics.mean(decap_times)
    }


def sig_benchmark(algorithm: str, num_iterations: int = 100) -> dict:
    print(" > Starting SIGNATURE benchmark...")
    key_times = []
    sign_times = []
    verify_times = []

    with open(f'{tmp}/test_message.txt', 'wb') as f:
        f.write(os.urandom(1024))

    for _ in tqdm(range(num_iterations), desc=f"Benchmark {algorithm}", unit="iter"):
        # Key generation
        start = time.time()
        generate_key(algorithm)
        key_times.append(time.time() - start)

        # Firma
        start = time.time()
        result = subprocess.run([
            openssl_path, "dgst", "-sign", f"{tmp}/private_key.pem", "-keyform", "PEM", "-sha256", "-out",
            f"{tmp}/signature.bin", f"{tmp}/test_message.txt"],
            shell=True, capture_output=True)
        sign_times.append(time.time() - start)
        print(f"\nCOMMAND: {' '.join(result.args)}") if debug["commands"] else None

        # Verifica
        start = time.time()
        result = subprocess.run(
            [openssl_path, "dgst", "-verify", f"{tmp}/public_key.pem", "-keyform", "PEM",
             "-sha256", "-signature", f"{tmp}/signature.bin", f"{tmp}/test_message.txt"],
            shell=True, capture_output=True)
        verify_times.append(time.time() - start)
        print(f"\nCOMMAND: {' '.join(result.args)}") if debug["commands"] else None

        cleanup_files(["private_key.pem", "public_key.pem", "signature.bin"])

    return {
        'key_generation_avg': statistics.mean(key_times),
        'signing_avg': statistics.mean(sign_times),
        'verification_avg': statistics.mean(verify_times)
    }


def run_benchmark(algorithms, test):
    results = {}

    # Reset the environment
    cleanup_files("*")
    print("   Environment reset.\n")

    # Run the benchmark
    for algo in algorithms:
        print(f"Algoritmo: {algo.upper()}")

        algo_result = kem_benchmark(algo) if test == 'kem' else sig_benchmark(algo)

        if algo_result:
            results[algo] = algo_result

        cleanup_files(["private_key.pem", "public_key.pem"])
        if test == 'signature':
            cleanup_files(["test_message.txt", "signature.bin"])

        print(f"  Benchmark completato.")
        print("\n")
    return results


def save_results(results):
    with open('benchmark_results.json', 'w') as f:
        json.dump(results, f, indent=4)

    print("All results saved in 'benchmark_results.json'")


def plot_benchmark(data, algorithms, colors, title, figsize, test_type):
    times = {
        "key_generation": [data[algo]["key_generation_avg"] for algo in reversed(algorithms)],
        "operation": [data[algo]["encapsulation_avg" if test_type == "kem" else "signing_avg"]
                      for algo in reversed(algorithms)],
        "verification": [data[algo]["decapsulation_avg" if test_type == "kem" else "verification_avg"]
                         for algo in reversed(algorithms)]
    }

    operations = ["Key Generation Time",
                  "Encapsulation Time" if test_type == "kem" else "Signing Time",
                  "Decapsulation Time" if test_type == "kem" else "Verification Time"]

    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=figsize, sharex=True)
    fig.suptitle(title, fontsize=18, y=0.995)

    for ax, operation, data in zip([ax1, ax2, ax3], operations, times.values()):
        bars = ax.barh(list(reversed(algorithms)), data, color=list(reversed(colors)))
        ax.set_title(operation)
        ax.set_xlabel("Time (seconds)")

        for rect in bars:
            width = rect.get_width()
            ax.text(
                width + width * 0.02,
                rect.get_y() + rect.get_height() / 2,
                f"{width:.6f}s",
                va="center",
                ha="left",
                fontsize=11
            )

    plt.tight_layout(h_pad=3)
    plt.show()
