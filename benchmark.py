import subprocess
import json
import os
import statistics
import sys
import time
from tqdm import tqdm
import matplotlib.pyplot as plt
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization

debug = {
    "first": True
}

try:
    logging.basicConfig(
        filename='benchmark.log',
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S',
        force=True
    )
except Exception as e:
    print(f"Error initializing logging: {e}")
    sys.exit(1)

openssl_path = "/opt/openssl-3.3.2/bin/openssl"
provider_path = "/opt/openssl-3.3.2/lib64/ossl-modules"
tmp = "./tmp"

ciphertext_path = f"{tmp}/ciphertext.bin"


def cleanup_files(files: list | str):
    if files == "*":
        if os.path.exists(tmp) and (os.listdir(tmp) != []):
            logging.warning("Cleaning up residual files in 'tmp' folder.")
            for file in os.listdir(tmp):
                os.remove(f"{tmp}/{file}")

        if os.path.exists(f"benchmark.log"):
            open(f"benchmark.log", 'w').close()
        else:
            print("Creating benchmark.log file...")
            with open(f"benchmark.log", 'w') as f:
                f.write("")

        logging.warning("All residual files deleted.\n")

    elif isinstance(files, list):
        for file in files:
            if os.path.exists(f"{tmp}/{file}"):
                os.remove(f"{tmp}/{file}")
    else:
        print("Error: cleanup_files() called with unsupported argument.")
        logging.error("Error: cleanup_files() called with unsupported argument.")


def generate_key(algorithm: str, key_size: int | None) -> dict:
    try:
        cleanup_files(["private_key.pem", "public_key.pem"])

        logging.info(f"Key generation for algorithm {algorithm.upper()} started.") if debug["first"] else None

        if algorithm == "ecdh":
            # Generate private key
            result = subprocess.run([
                openssl_path, "genpkey",
                "-algorithm", "EC",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-out", f"{tmp}/private_key.pem"
            ], capture_output=True, text=True, check=True)
            logging.debug(f"  > COMMAND: {' '.join(result.args)}") if debug["first"] else None
            logging.debug(f"  > Private Key {algorithm.upper()} generated successfully.") if debug["first"] else None

            # Generate public key
            result = subprocess.run([
                openssl_path, "pkey",
                "-in", f"{tmp}/private_key.pem",
                "-pubout",
                "-out", f"{tmp}/public_key.pem"
            ], capture_output=True, text=True, check=True)

            logging.debug(f"  > COMMAND: {' '.join(result.args)}") if debug["first"] else None
            logging.debug(f"  > Public Key {algorithm.upper()} generated successfully.\n") if debug["first"] else None

        elif "rsa" in algorithm:
            # Generate private key
            result = subprocess.run([
                openssl_path, "genpkey",
                "-algorithm", "RSA",
                "-pkeyopt", f"rsa_keygen_bits:{key_size}",
                "-out", f"{tmp}/private_key.pem"
            ], capture_output=True, text=True, check=True)
            logging.debug(f"  > COMMAND: {' '.join(result.args)}") if debug["first"] else None
            logging.debug(f"  > Private Key {algorithm.upper()} generated successfully.") if debug["first"] else None

            # Generate public key
            result = subprocess.run([
                openssl_path, "pkey",
                "-in", f"{tmp}/private_key.pem",
                "-pubout",
                "-out", f"{tmp}/public_key.pem"
            ], capture_output=True, text=True, check=True)
            logging.debug(f"  > COMMAND: {' '.join(result.args)}") if debug["first"] else None
            logging.debug(f"  > Public Key {algorithm.upper()} generated successfully.\n") if debug["first"] else None

        else:
            # Generate private key
            result = subprocess.run([
                openssl_path, 'genpkey',
                '-out', f'{tmp}/private_key.pem',
                '-algorithm', algorithm,
                '-provider', 'default',
                '-provider', 'oqsprovider',
                '-provider-path', provider_path
            ], capture_output=True, text=True, check=True)
            logging.debug(f"  > COMMAND: {' '.join(result.args)}") if debug["first"] else None
            logging.debug(f"  > Private Key {algorithm.upper()} generated successfully.") if debug["first"] else None

            # Generate public key
            result = subprocess.run([
                openssl_path, 'pkey',
                '-in', f'{tmp}/private_key.pem',
                '-pubout',
                '-out', f'{tmp}/public_key.pem',
                '-provider', 'oqsprovider',
                '-provider', 'default',
                '-provider-path', provider_path
            ], capture_output=True, text=True, check=True)
            logging.debug(f"  > COMMAND: {' '.join(result.args)}") if debug["first"] else None
            logging.debug(f"  > Public Key {algorithm.upper()} generated successfully.\n") if debug["first"] else None

        private_size = os.path.getsize(f'{tmp}/private_key.pem')
        public_size = os.path.getsize(f'{tmp}/public_key.pem')

        return {'private_size': private_size, 'public_size': public_size}
    except subprocess.CalledProcessError as e:
        print(f"Error in key generation for {algorithm.upper()}: {e.stderr}")
        logging.error(f"Error in key generation for {algorithm.upper()}: \n{e.stderr}")
        return {}


def kem_benchmark(algorithm: str, key_size: int | None, num_iterations: int = 100) -> dict:
    print(" > Starting KEM benchmark...")
    logging.info("\nStarting KEM benchmark...")

    keygen_times, encap_times, decap_times = [], [], []

    key_sizes = generate_key(algorithm, key_size)
    if not key_sizes:
        return {}

    for _ in tqdm(range(num_iterations), desc=f"Benchmark {algorithm}", unit="iter"):
        # Key generation
        start = time.time()
        generate_key(algorithm, key_size)
        keygen_times.append(time.time() - start)

        if algorithm == "ecdh":
            # Encapsulation
            start = time.time()
            result = subprocess.run([
                openssl_path, "pkeyutl",
                "-derive",
                "-inkey", f"{tmp}/private_key.pem",
                "-peerkey", f"{tmp}/public_key.pem",
                "-out", ciphertext_path
            ], shell=True, capture_output=True)
            encap_times.append(time.time() - start)
            logging.debug(f"COMMAND: {' '.join(result.args)}") if debug["first"] else None

            # Decapsulation: in ECDH, this is not needed since the shared secret is directly derived
            decap_times.append(0)

        elif "rsa" in algorithm:
            # Encapsulation
            start = time.time()
            result = subprocess.run([
                openssl_path, "pkeyutl",
                "-encrypt",
                "-inkey", f"{tmp}/public_key.pem",
                "-keyform", "PEM",
                "-out", ciphertext_path,
                "-pkeyopt"
            ], check=True, shell=True, capture_output=True)
            encap_times.append(time.time() - start)
            logging.debug(f"COMMAND: {' '.join(result.args)}") if debug["first"] else None

            # Decapsulation
            start = time.time()
            result = subprocess.run([
                openssl_path, "pkeyutl",
                "-decrypt",
                "-inkey", f"{tmp}/private_key.pem",
                "-keyform", "PEM",
                "-in", ciphertext_path,
                "-pkeyopt"
            ], shell=True, capture_output=True)
            decap_times.append(time.time() - start)
            logging.debug(f"COMMAND: {' '.join(result.args)}") if debug["first"] else None


        elif "kyber" in algorithm:
            # Encapsulation
            start = time.time()
            result = subprocess.run([
                openssl_path, "pkeyutl",
                "-encrypt",
                "-inkey", f"{tmp}/public_key.pem",
                "-keyform", "PEM",
                "-out", ciphertext_path,
                "-pkeyopt", "kem"
            ], check=True, shell=True, capture_output=True)
            encap_times.append(time.time() - start)
            logging.debug(f"COMMAND: {' '.join(result.args)}") if debug["first"] else None

            # Decapsulation
            start = time.time()
            result = subprocess.run([
                openssl_path, "pkeyutl",
                "-decrypt",
                "-inkey", f"{tmp}/private_key.pem",
                "-keyform", "PEM",
                "-in", ciphertext_path,
                "-pkeyopt", "kem"
            ], shell=True, capture_output=True)
            decap_times.append(time.time() - start)
            logging.debug(f"COMMAND: {' '.join(result.args)}") if debug["first"] else None

        if debug["first"]: debug["first"] = False
    return {
        'private_size': key_sizes['private_size'],
        'public_size': key_sizes['public_size'],
        'key_generation_avg': round(statistics.mean(keygen_times), 7),
        'encapsulation_avg': round(statistics.mean(encap_times), 7),
        'decapsulation_avg': round(statistics.mean(decap_times), 7),
    }


def sig_benchmark(message: bytes | None, algorithm: str, key_size: int | None, num_iterations: int = 100) -> dict:
    print(" > Starting SIGNATURE benchmark...")
    logging.info(f"\nStarting SIGNATURE benchmark...")

    # private_key, private_key, signature = None, None, None
    keygen_times, sign_times, verify_times = [], [], []

    if "rsa" in algorithm or "ecdsa" in algorithm:
        if algorithm == "ecdsa":
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif "rsa" in algorithm:
            if not key_size:
                raise ValueError("RSA requires a key size to be specified.")
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

        public_key = private_key.public_key()
        key_sizes = {
            'private_size': private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).__sizeof__(),
            'public_size': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).__sizeof__()
        }
    else:  # For PQC algorithms
        key_sizes = generate_key(algorithm, key_size)

    if not key_sizes:
        return {}

    for _ in tqdm(range(num_iterations), desc=f"Benchmark {algorithm}", unit="iter"):
        # Key Generation
        start = time.time()
        if "ecdsa" in algorithm:
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
        elif "rsa" in algorithm:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            public_key = private_key.public_key()
        else:
            generate_key(algorithm, key_size)
        keygen_times.append(time.time() - start)
        logging.debug(f"Key generation for {algorithm.upper()} completed.") if debug["first"] else None

        # Signing
        start = time.time()
        if "ecdsa" in algorithm:
            signature = private_key.sign(
                message, ec.ECDSA(hashes.SHA256())
            )
        elif "rsa" in algorithm:
            signature = private_key.sign(
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        else:  # For PQC algorithms
            result = subprocess.run([
                openssl_path, "dgst",
                "-sign", f"{tmp}/private_key.pem",
                "-keyform", "PEM",
                "-sha256",
                "-out", f"{tmp}/signature.bin",
                "message.txt"
            ], check=True, shell=True, capture_output=True)
            logging.debug(f"COMMAND: {' '.join(result.args)}") if debug["first"] else None
        sign_times.append(time.time() - start)
        logging.debug(f"Signing for {algorithm.upper()} completed.") if debug["first"] else None

        # Verification
        start = time.time()
        if "ecdsa" in algorithm:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif "rsa" in algorithm:
            public_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        else:
            result = subprocess.run(
                [openssl_path, "dgst", "-verify", f"{tmp}/public_key.pem", "-keyform", "PEM",
                 "-sha256", "-signature", f"{tmp}/signature.bin", "message.txt"],
                shell=True, capture_output=True)
            logging.debug(f"COMMAND: {' '.join(result.args)}") if debug["first"] else None
        verify_times.append(time.time() - start)
        logging.debug(f"Verification for {algorithm.upper()} completed.") if debug["first"] else None

        if debug["first"]: debug["first"] = False
    return {
        'private_size': key_sizes['private_size'],
        'public_size': key_sizes['public_size'],
        'key_generation_avg': round(statistics.mean(keygen_times), 7),
        'signing_avg': round(statistics.mean(sign_times), 7),
        'verification_avg': round(statistics.mean(verify_times), 7)
    }


def run_benchmark(algorithms, test: str, message: bytes | None) -> dict:
    results = {}
    algo_result = None

    # Reset the environment
    cleanup_files("*")

    # Run the benchmark
    for category in ['classical', 'pqc']:
        for algo in algorithms[category]:
            print(f"Algorithm - {algo['name'].upper()}")

            if test == 'KEM':
                algo_result = kem_benchmark(algo['name'], algo['key'])
            elif test == 'SIGNATURE':
                algo_result = sig_benchmark(
                    message=message,
                    algorithm=algo['name'],
                    key_size=algo['key'] if category == "classical" else None
                )

            if algo_result:
                results[algo['name']] = algo_result

            print(f"  Benchmark completato.\n")
            if not debug["first"]: debug["first"] = True
    return results


def save_results(results):
    with open('./results/benchmark_results.json', 'w') as f:
        json.dump(results, f, indent=4)

    print("All results saved in './results/benchmark_results.json'")


def plot_benchmark(data, algorithms, colors, title, suptitle_font, title_font, label_font,
                   size_key, size_ops, test_type, save_path=None):
    times = [data[algo]["key_generation_avg"] for algo in algorithms]

    # - - - - - - - - - - - - - - - Benchmark Key Generation - - - - - - - - - - - - - - -
    fig_key, ax = plt.subplots(figsize=size_key)
    fig_key.suptitle(t=title, fontsize=suptitle_font, fontweight='bold', y=0.98)

    bars = ax.bar(algorithms, times, color=colors, label=algorithms)
    ax.set_title("Key Generation Time", fontsize=title_font)
    ax.set_ylabel("Time (seconds)")
    ax.legend()
    ax.set_xticklabels([])

    max_height = max(times)
    ax.set_ylim(0, max_height * 1.1)

    for rect in bars:
        height = rect.get_height()
        ax.text(
            rect.get_x() + rect.get_width() / 2,
            height + height * 0.01,
            f"{height:.6f}s",
            va="bottom",
            ha="center",
            fontsize=label_font
        )

    plt.tight_layout()
    if save_path:
        plt.savefig(save_path + "keygen_benchmark.png")
    plt.show()

    # - - - - - - - - - - - - - - - - Benchmark Operations - - - - - - - - - - - - - - - - -
    times = {
        "operation": [data[algo]["encapsulation_avg" if test_type == "KEM" else "signing_avg"]
                      for algo in algorithms],
        "verification": [data[algo]["decapsulation_avg" if test_type == "KEM" else "verification_avg"]
                         for algo in algorithms]
    }
    operations = ["Encapsulation Time" if test_type == "KEM" else "Signing Time",
                  "Decapsulation Time" if test_type == "KEM" else "Verification Time"]

    fig1, (ax1, ax2) = plt.subplots(2, 1, figsize=size_ops, sharex=True)
    fig1.suptitle(t=title, fontsize=suptitle_font, fontweight='bold', y=0.98)

    for axis, operation, data in zip([ax1, ax2], operations, times.values()):
        bars = axis.bar(algorithms, data, color=colors, label=algorithms)
        axis.set_title(operation, fontsize=title_font)
        axis.set_ylabel("Time (seconds)")
        axis.legend()

        axis.set_xticklabels([])

        max_height = max(data)
        axis.set_ylim(0, max_height * 1.1)

        for rect in bars:
            height = rect.get_height()
            axis.text(
                rect.get_x() + rect.get_width() / 2,
                height + height * 0.01,
                f"{height:.6f}s",
                va="bottom",
                ha="center",
                fontsize=label_font
            )

    plt.tight_layout(h_pad=3)
    if save_path:
        plt.savefig(save_path + "ops_benchmark.png")

    plt.show()


def plot_key_sizes(data, algorithms, figsize, test_type, save_path=None):
    private_sizes = [data[algo]["private_size"] for algo in algorithms]
    public_sizes = [data[algo]["public_size"] for algo in algorithms]

    fig, ax = plt.subplots(figsize=figsize)
    bar_width = 0.4
    x = range(len(algorithms))

    ax.bar(x, private_sizes, bar_width, label="Private Key", color='#A80900')
    ax.bar([p + bar_width for p in x], public_sizes, bar_width, label="Public Key", color='green')

    ax.set_ylabel("Key Size (B)")
    ax.set_title(f"Comparison of Key Sizes - {test_type}", fontweight='bold')
    ax.set_xticks([p + bar_width / 2 for p in x])
    ax.set_xticklabels(algorithms, rotation=45)
    ax.legend()

    ax.set_ylim(0, max(private_sizes) * 1.1)

    for i in range(len(algorithms)):
        ax.text(
            x[i],
            private_sizes[i] + private_sizes[i] * 0.01,
            f"{private_sizes[i]}B",
            va="bottom",
            ha="center",
            fontsize=8
        )

        ax.text(
            x[i] + bar_width,
            public_sizes[i] + public_sizes[i] * 0.01,
            f"{public_sizes[i]}B",
            va="bottom",
            ha="center",
            fontsize=8
        )

    plt.tight_layout()
    if save_path:
        plt.savefig(save_path)
    plt.show()
