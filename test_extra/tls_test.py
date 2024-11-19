import subprocess
import time
import matplotlib.pyplot as plt

openssl_path = "/opt/openssl-3.3.2/bin/openssl"


def run_tls_handshake(group):
    server_cmd = [
        f"{openssl_path}", "s_server",
        "-cert", "server-cert.pem", "-prova2", "server-prova2.pem",
        "-groups", group, "-www", "-tls1_3"
    ]
    client_cmd = [
        f"{openssl_path}", "s_client",
        "-groups", group, "-connect", "localhost:4433"
    ]

    # Avvia il server in background
    server_proc = subprocess.Popen(server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)

    # Misura il tempo di handshake
    start_time = time.time()
    client_proc = subprocess.run(client_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    handshake_time = time.time() - start_time

    # Arresta il server
    server_proc.terminate()
    return handshake_time


groups = ["kyber512", "dilithium2"]
handshake_times = {}

for group in groups:
    time_taken = run_tls_handshake(group)
    handshake_times[group] = time_taken
    print(f"Handshake time for {group}: {time_taken:.4f} s")

plt.bar(handshake_times.keys(), handshake_times.values())
plt.xlabel("Gruppi")
plt.ylabel("Tempo di Handshake (s)")
plt.title("Performance TLS con algoritmi PQC")
plt.show()
