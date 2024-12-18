from benchmark import run_benchmark, save_results, plot_benchmark, plot_key_sizes
import json

execute = {
    "benchmark": False,
    "plot": True,
}

# %% Benchmarking
ALGORITHMS = {
    "KEM": {
        "classical": [
            {"name": "ecdh", "key": None},
            {"name": "rsa2048", "key": 2048},
            {"name": "rsa3072", "key": 3072},
            {"name": "rsa4096", "key": 4096},
        ],
        "pqc": [
            {"name": "kyber512", "key": None},
            {"name": "kyber768", "key": None},
            {"name": "kyber1024", "key": None},
        ]
    },
    "SIGNATURE": {
        "classical": [
            {"name": "rsa2048", "key": 2048},
            {"name": "rsa3072", "key": 2048},
            {"name": "ecdsa", "key": None},
        ],
        "pqc": [
            {"name": "dilithium2"},
            {"name": "dilithium3"},
            {"name": "dilithium5"},
            {"name": "sphincssha2128fsimple"},
            {"name": "sphincssha2128ssimple"},
            {"name": "falcon512"},
            {"name": "falcon1024"},
        ]
    }
}

results = {"KEM": {}, "SIGNATURE": {}}

if execute["benchmark"]:
    results["KEM"] = run_benchmark(ALGORITHMS["KEM"], test="KEM", message=None)

    message = b"This is a message for the Signature test. Enjoy!"
    results["SIGNATURE"] = run_benchmark(ALGORITHMS["SIGNATURE"], test="SIGNATURE", message=message)

    save_results(results)

# %% Visualization of the results
if execute["plot"]:
    with open("./results/benchmark_results.json", "r") as f:
        results = json.load(f)

    # KEM Benchmark
    if results["KEM"] != {} and False:
        plot_benchmark(
            data=results["KEM"],
            algorithms=[algo["name"] for algo in ALGORITHMS["KEM"]["classical"]]
                       + [algo["name"] for algo in ALGORITHMS["KEM"]["pqc"]],
            colors=['#5A6C7F', '#B36B00', '#3D8B3D', '#B22222', '#BDB76B', '#7F7F7F', '#8B4513'],
            title="Benchmark KEM Algorithms",
            size_key=(8, 4),  # (x, y) = (width, height)
            size_ops=(8, 8),
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
                       + [algo["name"] for algo in ALGORITHMS["KEM"]["pqc"]],
            figsize=(8, 4),
            test_type="KEM",
            save_path="./results/kem_key_sizes.png"
        )

    # SIGNATURE Benchmark
    if results["SIGNATURE"] != {}:
        plot_benchmark(
            data=results["SIGNATURE"],
            algorithms=[algo["name"] for algo in ALGORITHMS["SIGNATURE"]["classical"]]
                       + [algo["name"] for algo in ALGORITHMS["SIGNATURE"]["pqc"]],
            colors=['#8B2635', '#8583B2', '#255687', '#5D2E46', '#C68245',
                    '#18594F', '#6044A7', '#865929', '#7BA5A5', '#116D06'],
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
                       + [algo["name"] for algo in ALGORITHMS["SIGNATURE"]["pqc"]],
            figsize=(10, 5),
            test_type="SIGNATURE",
            save_path="./results/signature_key_sizes.png"
        )
