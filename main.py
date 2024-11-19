from benchmark import run_benchmark, save_results, cleanup_files

kem_algorithms = [
    'kyber512', 'kyber768', 'kyber1024'
]

sig_algorithms = [
    'dilithium2', 'dilithium3', 'dilithium5',
    'sphincssha2128fsimple', 'sphincsshake128fsimple',
    'falcon512', 'falcon1024',
]

results = {
    'KEM': {},
    'SIGNATURE': {}
}

results["KEM"] = run_benchmark(kem_algorithms, test='kem')
results["SIGNATURE"] = run_benchmark(sig_algorithms, test='signature')
save_results(results)
