import subprocess
import json
import os
import statistics
import time

openssl_path = "/opt/openssl-3.3.2/bin/openssl"
provider_path = "/opt/openssl-3.3.2/lib64/ossl-modules"
project_path = "./benchmark"


def cleanup_files(files: list = None):
    for file in files:
        if os.path.exists(file):
            os.remove(f"{project_path}/{file}")


def generate_key(algorithm: str):
    try:
        print(" > Generazione chiave...")
        keygen_cmd = [
            openssl_path, 'genpkey',
            '-provider', 'default',
            '-provider', 'oqsprovider',
            '-provider-path', provider_path,
            '-out', f'{project_path}/key.pem',
            '-algorithm', algorithm
        ]

        subprocess.run(keygen_cmd, capture_output=True, text=True, check=True)

        subprocess.run([
            openssl_path, 'pkey',
            '-in', f'{project_path}/key.pem',
            '-pubout',
            '-out', f'{project_path}/public_key.pem',
            '-provider', 'oqsprovider',
            '-provider', 'default',
            '-provider-path', provider_path
        ], check=True)

        print("   Chiave generata con successo.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Errore nella generazione chiave per {algorithm}: ")
        print(f"Comando: {' '.join(e.cmd)}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return False


def kem_benchmark(algorithm: str, num_iterations: int = 100) -> dict:
    print(" > Avvio benchmark KEM...")
    key_times = []
    encap_times = []
    decap_times = []

    for i in range(num_iterations):
        print(f"    - {i + 1}/{num_iterations} per KEM benchmark") if i % 20 == 0 or (i + 1) == num_iterations else None

        # Generazione chiavi
        start = time.time()
        keygen_cmd = f"{openssl_path} genpkey -algorithm {algorithm}"
        subprocess.run(keygen_cmd, shell=True, capture_output=True)
        key_times.append(time.time() - start)

        # Preparazione chiavi
        subprocess.run(f"{openssl_path} genpkey -algorithm {algorithm} -out {project_path}/private_key.pem", shell=True)
        subprocess.run(
            f"{openssl_path} pkey -in {project_path}/private_key.pem -pubout -out {project_path}/public_key.pem",
            shell=True)

        # Incapsulamento
        start = time.time()
        encap_cmd = f"{openssl_path} pkeyutl -encrypt -inkey {project_path}/public_key.pem -keyform PEM"
        subprocess.run(encap_cmd, shell=True, capture_output=True)
        encap_times.append(time.time() - start)

        # Decapsulamento
        start = time.time()
        decap_cmd = f"{openssl_path} pkeyutl -decrypt -inkey {project_path}/private_key.pem -keyform PEM"
        subprocess.run(decap_cmd, shell=True, capture_output=True)
        decap_times.append(time.time() - start)

    cleanup_files(["private_key.pem", "public_key.pem"])

    return {
        'key_generation_avg': statistics.mean(key_times),
        'encapsulation_avg': statistics.mean(encap_times),
        'decapsulation_avg': statistics.mean(decap_times)
    }


def sig_benchmark(algorithm: str, num_iterations: int = 100) -> dict:
    print(" > Avvio benchmark SIGNATURE...")
    key_times = []
    sign_times = []
    verify_times = []

    with open(f'{project_path}/test_message.txt', 'wb') as f:
        f.write(os.urandom(1024))

    for i in range(num_iterations):
        print(f" > Iterazione {i + 1}/{num_iterations} per Signature benchmark") if i % 20 == 0 else None

        # Generazione chiavi
        start = time.time()
        keygen_cmd = f"{openssl_path} genpkey -algorithm {algorithm}"
        subprocess.run(keygen_cmd, shell=True, capture_output=True)
        key_times.append(time.time() - start)

        # Preparazione chiavi
        subprocess.run(f"{openssl_path} genpkey -algorithm {algorithm} -out {project_path}/private_key.pem", shell=True)
        subprocess.run(
            f"{openssl_path} pkey -in {project_path}/private_key.pem -pubout -out {project_path}/public_key.pem",
            shell=True)

        # Firma
        start = time.time()
        sign_cmd = f"{openssl_path} dgst -sign {project_path}/private_key.pem -keyform PEM -sha256 -out {project_path}/signature.bin {project_path}/test_message.txt"
        subprocess.run(sign_cmd, shell=True, capture_output=True)
        sign_times.append(time.time() - start)

        # Verifica
        start = time.time()
        verify_cmd = f"{openssl_path} dgst -verify {project_path}/public_key.pem -keyform PEM -sha256 -signature {project_path}/signature.bin {project_path}/test_message.txt"
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

    for algo in algorithms:
        print(f"Algoritmo: {algo.upper()}")

        if not generate_key(algo):
            print("Errore nella generazione della chiave.")
            continue

        algo_result = kem_benchmark(algo) if test == 'kem' else sig_benchmark(algo)

        if algo_result:
            results[algo] = algo_result

        print(f" > Benchmark completato.")
        print("\n")
    return results


def save_results(results):
    with open('benchmark_results.json', 'w') as f:
        json.dump(results, f, indent=4)

    print("Risultati salvati in 'benchmark_results.json'")
