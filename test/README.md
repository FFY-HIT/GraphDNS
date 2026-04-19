# Large-Scale Experimental Validation

## Environment Requirements

### Hardware Requirements
- Memory: 8 GB or more
- Storage: 512 GB SSD

### Software Requirements
- Operating System: Ubuntu 22.04.5 LTS
- Compiler: g++ with C++17 support
- Logic Programming Engine: Soufflé 2.5

## Dataset Layout

LogicDNS expects input datasets to follow a specific directory structure:

```text
dataset/
├── a.com/
│   ├── 1.a.com.txt
│   ├── 2.a.com.txt
│   └── metadata.json
└── b.com/
    ├── 1.b.com.txt
    ├── 2.b.com.txt
    └── metadata.json
```

Notes:

* Each subdirectory corresponds to one domain or a related group of zone files
* `*.txt` files store zone data
* `metadata.json` provides metadata such as associated authoritative servers
* The verifier scans the dataset automatically based on this layout

Public Census dataset:

* [https://zenodo.org/records/3905968](https://zenodo.org/records/3905968)

## Performance Evaluation

### Step 1: Generate the C++ verifier from the Soufflé program

```bash
souffle -g verifier.cpp dns_verify.dl
```

### Step 2: Compile the verifier

```bash
g++ -O3 -std=c++17 -fopenmp main.cpp -o direct_verifier
```

### Step 3: Run the large-scale evaluation

This experiment compares performance with GRoot. Accordingly, the verifier is configured to enable the same verification properties as GRoot.

```bash
chmod +x ./run_experiments.sh
./run_experiments.sh
```

## Experimental Scope

LogicDNS supports several categories of experiments:

### 1. Detection Coverage Evaluation

Compare LogicDNS and GRoot on synthetic datasets to validate:

* equivalent capability on shared path vulnerabilities
* additional coverage for orphan and shadow records

### 2. Real-World Validation

Evaluate LogicDNS on production DNS data (e.g., ZDNS) to determine:

* whether real historical errors can be uncovered
* whether the framework provides practical operational value

### 3. Large-Scale Performance Evaluation

Use the Census dataset to measure:

* end-to-end runtime
* scalability
* runtime stability
* resource consumption