import subprocess
import json
import os
import statistics
import time
from tqdm import tqdm
import matplotlib.pyplot as plt
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes, serialization

debug = {
    "cleanup": False,
    "first": True
}

logging.basicConfig(
    filename='benchmark.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

openssl_path = "/opt/openssl-3.3.2/bin/openssl"
provider_path = "/opt/openssl-3.3.2/lib64/ossl-modules"
tmp = "./tmp"


def cleanup_files(files: list | str):
    if files == "*":
        if os.path.exists(tmp) and (os.listdir(tmp) != []):
            logging.warning("Cleaning up residual files in 'tmp' folder.")
            for file in os.listdir(tmp):
                os.remove(f"{tmp}/{file}")

        if os.path.exists(f"benchmark.log"):
            os.remove(f"benchmark.log")

        logging.warning("All residual files deleted.\n")

    elif isinstance(files, list):
        for file in files:
            if os.path.exists(f"{tmp}/{file}"):
                os.remove(f"{tmp}/{file}")
    else:
        print("Error: cleanup_files() called with unsupported argument.")
        logging.error("Error: cleanup_files() called with unsupported argument.")


def generate_key(algorithm: str) -> dict:
    try:
        logging.info(f"Key generation for algorithm {algorithm.upper()} started.") if debug["first"] else None

        result = subprocess.run([
            openssl_path, 'genpkey',
            '-provider', 'default',
            '-provider', 'oqsprovider',
            '-provider-path', provider_path,
            '-out', f'{tmp}/private_key.pem',
            '-algorithm', algorithm
        ], capture_output=True, text=True, check=True)

        logging.debug(f"  > COMMAND: {' '.join(result.args)}") if debug["first"] else None
        logging.debug(f"  > Private Key {algorithm.upper()} generated successfully.") if debug["first"] else None

        result = subprocess.run([
            openssl_path, 'pkey',
            '-in', f'{tmp}/private_key.pem',
            '-pubout',
            '-out', f'{tmp}/public_key.pem',
            '-provider', 'oqsprovider',
            '-provider', 'default',
            '-provider-path', provider_path
        ], check=True)

        logging.debug(f"  > COMMAND: {' '.join(result.args)}") if debug["first"] else None
        logging.debug(f"  > Public Key {algorithm.upper()} generated successfully.\n") if debug["first"] else None

        private_size = os.path.getsize(f'{tmp}/private_key.pem')
        public_size = os.path.getsize(f'{tmp}/public_key.pem')
        if debug["first"]: debug["first"] = False

        return {'private_size': private_size, 'public_size': public_size}
    except subprocess.CalledProcessError as e:
        print(f"Error in key generation for {algorithm.upper()}: ")
        logging.error(f"Error in key generation for {algorithm.upper()}: \n{e.stderr}")
        return {}


def kem_benchmark(algorithm: str, num_iterations: int = 100) -> dict:
    print(" > Starting KEM benchmark...")
    logging.info("Starting KEM benchmark...")

    keygen_times = []
    encap_times = []
    decap_times = []

    key_sizes = generate_key(algorithm)
    if not key_sizes:
        return {}

    for _ in tqdm(range(num_iterations), desc=f"Benchmark {algorithm}", unit="iter"):
        # Key generation
        start = time.time()
        generate_key(algorithm)
        keygen_times.append(time.time() - start)

        # Encapsulation
        start = time.time()
        result = subprocess.run([
            openssl_path, "pkeyutl", "-encrypt", "-inkey", f"{tmp}/public_key.pem", "-keyform", "PEM"],
            shell=True, capture_output=True)
        encap_times.append(time.time() - start)
        logging.debug(f"COMMAND: {' '.join(result.args)}") if debug["first"] else None

        # Decapsulation
        start = time.time()
        result = subprocess.run([
            openssl_path, "pkeyutl", "-decrypt", "-inkey", f"{tmp}/private_key.pem", "-keyform", "PEM"],
            shell=True, capture_output=True)
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


def kem_rsa_benchmark(algorithm: str, key_size: int, num_iterations: int = 100) -> dict:
    print(f" > Starting KEM benchmark for {algorithm.upper()}")
    logging.info(f"Starting KEM benchmark for {algorithm.upper()}.")

    keygen_times = []
    encap_times = []
    decap_times = []

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

    for _ in tqdm(range(num_iterations), desc=f"Benchmark {algorithm}", unit="iter"):
        # Key Generation
        start = time.time()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        keygen_times.append(time.time() - start)
        logging.debug(f"Key generation for {algorithm.upper()} completed.") if debug["first"] else None

        # Encapsulation
        message = b"Test Message for RSA KEM"
        start = time.time()
        ciphertext = public_key.encrypt(
            message, OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        encap_times.append(time.time() - start)
        logging.debug(f"Encapsulation for {algorithm.upper()} completed.") if debug["first"] else None

        # Decapsulation
        start = time.time()
        private_key.decrypt(
            ciphertext,
            OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        decap_times.append(time.time() - start)
        logging.debug(f"Decapsulation for {algorithm.upper()} completed.") if debug["first"] else None

        if debug["first"]: debug["first"] = False
    return {
        'private_size': key_sizes['private_size'],
        'public_size': key_sizes['public_size'],
        'key_generation_avg': round(statistics.mean(keygen_times), 7),
        'encapsulation_avg': round(statistics.mean(encap_times), 7),
        'decapsulation_avg': round(statistics.mean(decap_times), 5)
    }


def sig_benchmark(message: bytes | None, algorithm: str, key_size: int | None, num_iterations: int = 100) -> dict:
    print(" > Starting SIGNATURE benchmark...")
    logging.info(f"Starting SIGNATURE benchmark for {algorithm.upper()}.")

    keygen_times = []
    sign_times = []
    verify_times = []

    key_sizes = {}
    private_key = None

    if "ecdsa" in algorithm:
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif "rsa" in algorithm:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    else:
        key_sizes = generate_key(algorithm)

    if "rsa" in algorithm or "ecdsa" in algorithm:
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
            generate_key(algorithm)
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
        else:
            result = subprocess.run([
                openssl_path, "dgst", "-sign", f"{tmp}/private_key.pem", "-keyform", "PEM", "-sha256", "-out",
                f"{tmp}/signature.bin", "message.txt"],
                shell=True, capture_output=True)
            logging.debug(f"COMMAND: {' '.join(result.args)}") if debug["first"] else None
        sign_times.append(time.time() - start)
        logging.debug(f"Signing for {algorithm.upper()} completed.") if debug["first"] else None

        # Verification
        start = time.time()
        if "ecdsa" in algorithm:
            public_key.verify(
                signature, message, ec.ECDSA(hashes.SHA256())
            )
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
                if category == "classical":
                    algo_result = kem_rsa_benchmark(algo['name'], algo['key'])
                else:
                    algo_result = kem_benchmark(algo['name'])
            elif test == 'SIGNATURE':
                algo_result = sig_benchmark(
                    message=message,
                    algorithm=algo['name'],
                    key_size=algo['key'] if category == "classical" else None
                )

            if algo_result:
                results[algo['name']] = algo_result

            print(f"  Benchmark completato.\n")

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
