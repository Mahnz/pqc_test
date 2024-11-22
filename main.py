from benchmark import run_benchmark, save_results, plot_benchmark, plot_key_sizes
import json

execute = {
    "benchmark":
    # True,
        False,
    "plot":
    #         False,
        True,
}

# %% Benchmarking
ALGORITHMS = {
    "KEM": {
        "classical": [
            {"name": "rsa2048", "key": 2048},
            {"name": "rsa3072", "key": 3072},
            {"name": "rsa4096", "key": 4096},
        ],
        "pqc": [
            "kyber512", "kyber768", "kyber1024",
        ]
    },
    "SIGNATURE": {
        "classical": [
            {"name": "rsa2048", "key": 2048},
            {"name": "rsa3072", "key": 2048},
            {"name": "ecdsa", "key": None},
        ],
        "pqc": [
            "dilithium2", "dilithium3", "dilithium5",
            "sphincssha2128fsimple", "sphincssha2128ssimple",
            "falcon512", "falcon1024",
        ]
    }
}

results = {"KEM": {}, "SIGNATURE": {}}

if execute["benchmark"]:
    results["KEM"] = run_benchmark(ALGORITHMS["KEM"], test="KEM")
    results["SIGNATURE"] = run_benchmark(ALGORITHMS["SIGNATURE"], test="SIGNATURE")

    save_results(results)

# %% Visualization of the results
if execute["plot"]:
    with open("./results/benchmark_results.json", "r") as f:
        results = json.load(f)

    # KEM Benchmark
    plot_benchmark(
        data=results["KEM"],
        algorithms=[algo["name"] for algo in ALGORITHMS["KEM"]["classical"]]
                   + ALGORITHMS["KEM"]["pqc"],
        colors=['#5A6C7F', '#B36B00', '#3D8B3D', '#B22222', '#BDB76B', '#7F7F7F'],
        title="Benchmark KEM Algorithms",
        size_key=(7, 4),  # (x, y) = (width, height)
        size_ops=(7, 8),
        suptitle_font=10,
        title_font=10,
        label_font=9,
        test_type="KEM",
        save_path="./results/kem_"
    )

    # KEM Keys sizes
    plot_key_sizes(
        data=results["KEM"] if "KEM" in results else results["SIGNATURE"],
        algorithms=[algo["name"] for algo in ALGORITHMS["KEM"]["classical"]]
                   + ALGORITHMS["KEM"]["pqc"],
        figsize=(7, 4),
        test_type="KEM",
        save_path="./results/kem_"
    )

    # Signature Benchmark
    plot_benchmark(
        data=results["SIGNATURE"],
        algorithms=[algo["name"] for algo in ALGORITHMS["SIGNATURE"]["classical"]]
                   + ALGORITHMS["SIGNATURE"]["pqc"],
        colors=['#8B4513', '#2F4F4F', '#556B2F', '#8B0000', '#483D8B',
                '#2E8B57', '#6A5ACD', '#4682B4', '#D2691E', '#9ACD32'],
        title="Benchmark Signature Algorithms",
        size_key=(11, 6),  # (x, y) = (width, height)
        size_ops=(11, 11),
        suptitle_font=16,
        title_font=12,
        label_font=12,
        test_type="SIGNATURE",
        save_path="./results/signature_"
    )

    # SIGNATURE Keys sizes
    plot_key_sizes(
        data=results["SIGNATURE"],
        algorithms=[algo["name"] for algo in ALGORITHMS["SIGNATURE"]["classical"]]
                   + ALGORITHMS["SIGNATURE"]["pqc"],
        figsize=(10, 5),
        test_type="SIGNATURE",
        save_path="./results/signature_key_sizes.png"
    )
