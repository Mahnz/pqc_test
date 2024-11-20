import subprocess
import json
import os
import statistics
import time
from tqdm import tqdm

openssl_path = "/opt/openssl-3.3.2/bin/openssl"
provider_path = "/opt/openssl-3.3.2/lib64/ossl-modules"
tmp = "./tmp"

debug = {
    "keygen": False,
}


def cleanup_files(files: list = None):
    for file in files:
        if os.path.exists(file):
            os.remove(f"{tmp}/{file}")


def generate_key(algorithm: str):
    try:
        print(" > Generating the keys...") if debug["keygen"] else None

        subprocess.run([
            openssl_path, 'genpkey',
            '-provider', 'default',
            '-provider', 'oqsprovider',
            '-provider-path', provider_path,
            '-out', f'{tmp}/private_key.pem',
            '-algorithm', algorithm
        ], capture_output=True, text=True, check=True)

        print("   Private key generated.") if debug["keygen"] else None

        subprocess.run([
            openssl_path, 'pkey',
            '-in', f'{tmp}/private_key.pem',
            '-pubout',
            '-out', f'{tmp}/public_key.pem',
            '-provider', 'oqsprovider',
            '-provider', 'default',
            '-provider-path', provider_path
        ], check=True)

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
        encap_cmd = f"{openssl_path} pkeyutl -encrypt -inkey {tmp}/public_key.pem -keyform PEM"
        subprocess.run(encap_cmd, shell=True, capture_output=True)
        encap_times.append(time.time() - start)

        # Decapsulation
        start = time.time()
        decap_cmd = f"{openssl_path} pkeyutl -decrypt -inkey {tmp}/private_key.pem -keyform PEM"
        subprocess.run(decap_cmd, shell=True, capture_output=True)
        decap_times.append(time.time() - start)

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
        sign_cmd = f"{openssl_path} dgst -sign {tmp}/private_key.pem -keyform PEM -sha256 -out {tmp}/signature.bin {tmp}/test_message.txt"
        subprocess.run(sign_cmd, shell=True, capture_output=True)
        sign_times.append(time.time() - start)

        # Verifica
        start = time.time()
        verify_cmd = f"{openssl_path} dgst -verify {tmp}/public_key.pem -keyform PEM -sha256 -signature {tmp}/signature.bin {tmp}/test_message.txt"
        subprocess.run(verify_cmd, shell=True, capture_output=True)
        verify_times.append(time.time() - start)

        cleanup_files(["private_key.pem", "public_key.pem", "test_message.txt", "signature.bin"])

    return {
        'key_generation_avg': statistics.mean(key_times),
        'signing_avg': statistics.mean(sign_times),
        'verification_avg': statistics.mean(verify_times)
    }


def run_benchmark(algorithms, test):
    results = {}

    if os.path.exists(tmp) and (os.listdir(tmp) != []):
        print(" > Residual files found in 'tmp'. Cleaning up...")
        for file in os.listdir(tmp):
            os.remove(f"{tmp}/{file}")

        print("   Environment reset.\n")

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

    print("Risultati salvati in 'benchmark_results.json'")
