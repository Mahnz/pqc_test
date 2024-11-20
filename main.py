from benchmark import run_benchmark, save_results, plot_benchmark
import json

execute = {
    "benchmark": False,
    "visualization": True
}

# %% Benchmarking
kem_algorithms = ["kyber512", "kyber768", "kyber1024"]

sig_algorithms = [
    "dilithium2", "dilithium3", "dilithium5",
    "sphincssha2128fsimple", "sphincsshake128fsimple",
    "falcon512", "falcon1024",
]

results = {"KEM": {}, "SIGNATURE": {}}

if execute["benchmark"]:
    results["KEM"] = run_benchmark(kem_algorithms, test="kem")
    results["SIGNATURE"] = run_benchmark(sig_algorithms, test="signature")
    save_results(results)

# %% Visualization of the results


if execute["visualization"]:
    with open("benchmark_results.json", "r") as f:
        results = json.load(f)

    # KEM Benchmark
    plot_benchmark(
        data=results["KEM"],
        algorithms=kem_algorithms,
        colors=['#166537', '#2774a7', '#94251a'],
        title="Benchmark KEM Algorithms",
        figsize=(15, 10),
        test_type="kem"
    )

    # Signature Benchmark
    plot_benchmark(
        data=results["SIGNATURE"],
        algorithms=sig_algorithms,
        colors=['#166537', '#2774a7', '#94251a', '#8B4513', '#4B0082', '#FF8C00', '#008080'],
        title="Benchmark Signature Algorithms",
        figsize=(17, 17),
        test_type="signature"
    )
