from benchmark import run_benchmark, save_results, plot_benchmark, plot_key_sizes
import json

execute = {
    "benchmark": False,
    "visualization": True
}

# %% Benchmarking
kem_algorithms = ["kyber512", "kyber768", "kyber1024"]

sig_algorithms = [
    "dilithium2", "dilithium3", "dilithium5",
    "sphincssha2128fsimple", "sphincssha2128ssimple",
    "falcon512", "falcon1024",
]

results = {"KEM": {}, "SIGNATURE": {}}

if execute["benchmark"]:
    results["KEM"] = run_benchmark(kem_algorithms, test="kem")
    results["SIGNATURE"] = run_benchmark(sig_algorithms, test="signature")
    save_results(results)

# %% Visualization of the results
if execute["visualization"]:
    with open("./results/benchmark_results.json", "r") as f:
        results = json.load(f)

    # KEM Benchmark
    plot_benchmark(
        data=results["KEM"],
        algorithms=kem_algorithms,
        colors=['#166537', '#2774a7', '#94251a'],
        title="Benchmark KEM Algorithms",
        size_key=(5, 4),  # (x, y) = (width, height)
        size_ops=(5, 8),
        suptitle_font=10,
        title_font=10,
        label_font=9,
        test_type="kem",
        save_path="./results/kem_"
    )

    # Signature Benchmark
    plot_benchmark(
        data=results["SIGNATURE"],
        algorithms=sig_algorithms,
        colors=['#166537', '#2774a7', '#94251a', '#8B4513', '#4B0082', '#FF8C00', '#008080'],
        title="Benchmark Signature Algorithms",
        size_key=(11, 6),  # (x, y) = (width, height)
        size_ops=(11, 11),
        suptitle_font=16,
        title_font=12,
        label_font=12,
        test_type="signature",
        save_path="./results/signature_"
    )

    # Keys sizes
    plot_key_sizes(
        data=results["KEM"] if "KEM" in results else results["SIGNATURE"],
        algorithms=kem_algorithms,
        figsize=(6, 4),
        save_path="./results/kem_"
    )

    plot_key_sizes(
        data=results["SIGNATURE"],
        algorithms=sig_algorithms,
        figsize=(10, 5),
        save_path="./results/signature_"
    )
