import subprocess
import sys
import time
import os

openssl_path = "/opt/openssl-3.3.2/bin/openssl"
message = b"Messaggio di esempio"

providers = [
    '-provider', 'default',
    '-provider', 'oqsprovider',
    '-provider-path', '/opt/openssl-3.3.2/lib64/ossl-modules'
]
algorithms = ['dilithium2', 'dilithium3', 'dilithium5', 'falcon512', 'sphincssha2128fsimple', 'kyber512']
iterations = 5

results = []

for algorithm in algorithms:
    print(f"\nTesting {algorithm}")
    keygen_times = []
    sign_encrypt_times = []
    verify_decrypt_times = []
    priv_key_sizes = []
    pub_key_sizes = []
    sig_cipher_sizes = []

    for i in range(iterations):
        # Generazione delle chiavi
        start_time = time.time()
        result = subprocess.run(
            [openssl_path, 'genpkey', '-algorithm', algorithm, '-out', './prova2/priv.pem'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        keygen_time = time.time() - start_time

        if result.returncode != 0:
            print(f"Errore durante la generazione delle chiavi per l'algoritmo {algorithm}:")
            print(result.stderr.decode())
            sys.exit(1)  # Interrompe l'esecuzione dello script
        keygen_times.append(keygen_time)

        # Estrazione della chiave pubblica
        result = subprocess.run(
            [openssl_path, 'pkey', '-in', './prova2/priv.pem', '-pubout', '-out', './prova2/pub.pem'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        if result.returncode != 0:
            print(f"Errore durante l'estrazione della chiave pubblica per l'algoritmo {algorithm}:")
            print(result.stderr.decode())
            sys.exit(1)

        # Misura dimensione delle chiavi
        priv_key_size = os.path.getsize('prova2/priv.pem')
        pub_key_size = os.path.getsize('prova2/pub.pem')
        priv_key_sizes.append(priv_key_size)
        pub_key_sizes.append(pub_key_size)

        # Scrittura del messaggio
        with open('message.txt', 'wb') as f:
            f.write(message)

        if 'kyber' in algorithm:
            # Cifratura
            start_time = time.time()
            result = subprocess.run([openssl_path, 'pkeyutl', '-encrypt', '-in', 'message.txt',
                                     '-pubin', '-inkey', './prova2/pub.pem', '-out', './prova2/cipher.bin'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            encrypt_time = time.time() - start_time

            if result.returncode != 0:
                print(f"Errore durante la cifratura per l'algoritmo {algorithm}:")
                print(result.stderr.decode())
                sys.exit(1)

            sign_encrypt_times.append(encrypt_time)

            # Decifratura
            start_time = time.time()
            result = subprocess.run([openssl_path, 'pkeyutl', '-decrypt', '-in', './prova2/cipher.bin',
                                     '-inkey', './prova2/priv.pem', '-out', 'decrypted.txt'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            decrypt_time = time.time() - start_time

            if result.returncode != 0:
                print(f"Errore durante la decifratura per l'algoritmo {algorithm}:")
                print(result.stderr.decode())
                sys.exit(1)

            verify_decrypt_times.append(decrypt_time)

            # Misura dimensione del testo cifrato
            cipher_size = os.path.getsize('prova2/cipher.bin')
            sig_cipher_sizes.append(cipher_size)

            # Verifica correttezza decifratura
            with open('decrypted.txt', 'rb') as f:
                decrypted_message = f.read()

            assert decrypted_message == message, "<!!!!   Decifratura fallita   !!!!>"
        else:
            # Firma
            start_time = time.time()
            result = subprocess.run([openssl_path, 'pkeyutl', '-sign', '-in', 'message.txt',
                                     '-inkey', './prova2/priv.pem', '-out', './prova2/signature.bin'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sign_time = time.time() - start_time

            if result.returncode != 0:
                print(f"Errore durante la firma per l'algoritmo {algorithm}:")
                print(result.stderr.decode())
                sys.exit(1)
            sign_encrypt_times.append(sign_time)

            # Verifica
            start_time = time.time()
            result = subprocess.run([openssl_path, 'pkeyutl', '-verify', '-in', 'message.txt',
                                     '-sigfile', './prova2/signature.bin', '-pubin', '-inkey', './prova2/pub.pem'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            verify_time = time.time() - start_time

            if result.returncode != 0:
                print(f"Errore durante la verifica per l'algoritmo {algorithm}:")
                print(result.stderr.decode())
                sys.exit(1)
            verify_decrypt_times.append(verify_time)

            # Misura dimensione della firma
            signature_size = os.path.getsize('prova2/signature.bin')
            sig_cipher_sizes.append(signature_size)

        # Pulizia file temporanei
        for file in ['./prova2/priv.pem', './prova2/pub.pem', 'message.txt', './prova2/signature.bin', './prova2/cipher.bin',
                     'decrypted.txt']:
            if os.path.exists(file):
                os.remove(file)

    avg_keygen_time = sum(keygen_times) / iterations
    avg_sign_encrypt_time = sum(sign_encrypt_times) / iterations
    avg_verify_decrypt_time = sum(verify_decrypt_times) / iterations
    avg_priv_key_size = sum(priv_key_sizes) / iterations
    avg_pub_key_size = sum(pub_key_sizes) / iterations
    avg_sig_cipher_size = sum(sig_cipher_sizes) / iterations

    results.append({
        'Algorithm': algorithm,
        'KeyGenTime': avg_keygen_time,
        'SignEncryptTime': avg_sign_encrypt_time,
        'VerifyDecryptTime': avg_verify_decrypt_time,
        'PrivKeySize': avg_priv_key_size,
        'PubKeySize': avg_pub_key_size,
        'SigCipherSize': avg_sig_cipher_size
    })

    # Stampa risultati
    print(f"Media tempo generazione chiavi: {avg_keygen_time:.4f} s")
    print(f"Media dimensione chiave privata: {avg_priv_key_size:.0f} bytes")
    print(f"Media dimensione chiave pubblica: {avg_pub_key_size:.0f} bytes")

    if 'kyber' in algorithm:
        print(f"Media tempo cifratura: {avg_sign_encrypt_time:.4f} s")
        print(f"Media tempo decifratura: {avg_verify_decrypt_time:.4f} s")
        print(f"Media dimensione testo cifrato: {avg_sig_cipher_size:.0f} bytes")
    else:
        print(f"Media tempo firma: {avg_sign_encrypt_time:.4f} s")
        print(f"Media tempo verifica: {avg_verify_decrypt_time:.4f} s")
        print(f"Media dimensione firma: {avg_sig_cipher_size:.0f} bytes")

    print()
