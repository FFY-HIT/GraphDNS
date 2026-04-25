## Environment Requirements

### Hardware Requirements

* Memory: 8 GB or higher
* Storage: 512 GB SSD

### Software Requirements

* Operating System: Ubuntu 22.04.5 LTS
* Compiler: `g++` with C++17 support
* Logic Programming Engine: Soufflé 2.5

## Execution Steps

### Step 1: Generate the C++ verification code

```bash
souffle -g verifier.cpp dns_verify.dl
```

### Step 2: Compile the verifier

```bash
g++ -O3 -std=c++17 -fopenmp main.cpp -o direct_verifier
```

### Step 3: Run the verification

```bash
./direct_verifier ./synthetic_dataset
```

## Outputs

Depending on the enabled rules, GraphDNS may generate:

* error reports
* intermediate fact files
* closure/path outputs
* performance statistics

Typical outputs include:

* `Error`
* `ShadowRecord`
* `OrphanRecord`
* `CleanRecord`
