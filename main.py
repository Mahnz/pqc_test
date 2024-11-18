import subprocess
import time


def test_handshake(group):
    server_cmd = [
        "openssl", "s_server",
        "-cert", "server-cert.pem", "-key", "server-key.pem",
        "-groups", group, "-www", "-tls1_3"
    ]
    client_cmd = [
        "openssl", "s_client",
        "-groups", group, "-connect", "localhost:4433"
    ]
    # Avvia il server in background
    server_proc = subprocess.Popen(server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)  # Tempo per avviare il server

    # Esegui il client e misura il tempo
    start_time = time.time()
    client_proc = subprocess.run(client_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    handshake_time = time.time() - start_time

    # Arresta il server
    server_proc.terminate()

    # Ritorna il tempo del handshake
    return handshake_time, client_proc.stdout.decode()


# Testa algoritmi PQC e tradizionali
groups = ["kyber512", "x25519"]
results = {}
for group in groups:
    handshake_time, output = test_handshake(group)
    results[group] = handshake_time
    print(f"Group: {group}, Handshake Time: {handshake_time:.4f} s")
