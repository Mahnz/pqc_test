import subprocess
import time
import matplotlib.pyplot as plt

openssl_path = "/opt/openssl-3.3.2/bin/openssl"


def run_openssl_kem(algorithm):
    cmd_encap = [
        f"{openssl_path}", "pkeyutl",
        "-encrypt", "-inkey", "prova2.pem",
        "-keyform", "pem", "-pkeyopt", f"kem_alg:{algorithm}"
    ]

    cmd_decap = [
        f"{openssl_path}", "pkeyutl",
        "-decrypt", "-inkey", "prova2.pem",
        "-keyform", "pem", "-pkeyopt", f"kem_alg:{algorithm}"
    ]

    start_encap = time.time()
    subprocess.run(cmd_encap, capture_output=True)
    encap_time = time.time() - start_encap

    start_decap = time.time()
    subprocess.run(cmd_decap, capture_output=True)
    decap_time = time.time() - start_decap

    return {"encapsulation": encap_time, "decapsulation": decap_time}


def run_openssl_signature(algorithm):
    cmd_sign = [
        f"{openssl_path}", "pkeyutl",
        "-sign", "-inkey", "prova2.pem",
        "-keyform", "pem", "-pkeyopt", f"sig_alg:{algorithm}"
    ]
    cmd_verify = [
        f"{openssl_path}", "pkeyutl",
        "-verify", "-inkey", "prova2.pem",
        "-keyform", "pem", "-pkeyopt", f"sig_alg:{algorithm}"
    ]

    start_sign = time.time()
    subprocess.run(cmd_sign, capture_output=True)
    sign_time = time.time() - start_sign

    start_verify = time.time()
    subprocess.run(cmd_verify, capture_output=True)
    verify_time = time.time() - start_verify

    return {"sign": sign_time, "verify": verify_time}


kem_algorithms = ["kyber512", "kyber768", "kyber1024"]
signature_algorithms = ["dilithium2", "dilithium3", "dilithium5", "sphincssha2128fsimple", "sphincsshake128fsimple",
                        "sphincssha2128ssimple", "sphincssha2192fsimple", ]

results = {"kem": {}, "signature": {}}

# Test KEM
for kem in kem_algorithms:
    print(f"Testing KEM: {kem}...")
    results["kem"][kem] = run_openssl_kem(kem)
    print(f"Results for {kem}: {results['kem'][kem]}")
    print()

print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")

for sig in signature_algorithms:
    print(f"Testing Signature: {sig}...")
    results["signature"][sig] = run_openssl_signature(sig)
    print(f"Results for {sig}: {results['signature'][sig]}")
    print()

for category, algos in results.items():
    for algo, metrics in algos.items():
        for op, time_taken in metrics.items():
            plt.bar(f"{algo} ({op})", time_taken, label=f"{algo} ({op})")

plt.figure(figsize=(25, 10))
plt.xlabel("Operazioni")
plt.ylabel("Tempo (s)")
plt.title("Performance degli algoritmi PQC")
plt.show()
