
# GraphDNS: Resolution Relation Graph Abstraction for Large-Scale Analysis of Static DNS Configurations

<!-- <p align="center">
  <img src="docs/logo.png" alt="GraphDNS Logo" width="160"/>
</p> -->

<p align="center">

  <img src="https://img.shields.io/badge/license-MIT-green" alt="license">
  <img src="https://img.shields.io/badge/platform-Ubuntu%2022.04-orange" alt="platform">
  <img src="https://img.shields.io/badge/language-C%2B%2B17%20%7C%20Souffl%C3%A9%202.5-purple" alt="language">
  <img src="https://img.shields.io/badge/domain-DNS%20Security-red" alt="domain">
  <img src="https://img.shields.io/badge/scalability-10M%2B%20records-success" alt="scalability">
</p>

---

## Overview

**GraphDNS** is a research-oriented framework for large-scale DNS configuration verification.  
Rather than modeling DNS verification as a problem of constructing queries and simulating resolution paths, GraphDNS reformulates it as:

> **the direct computation of the global resolution semantics induced by static configurations**

Under this perspective, GraphDNS uniformly characterizes and detects three classes of DNS configuration errors:

- **Path Vulnerabilities**
- **Orphan Records**
- **Shadow Records**

The system adopts a **C++ and Soufflé Datalog** two-stage architecture and supports efficient verification over tens of millions of DNS resource records.

---

## Motivation

Most existing DNS verification systems are **query-driven**.  
They construct queries, partition the query space, and simulate resolution paths in order to expose errors.

This design works well for path-level failures, but it has two fundamental limitations:

1. It focuses on **behaviors exposed by queries**
2. It is less effective at uniformly characterizing anomalies that **exist in the configuration itself but may not be directly exposed by any single query**

GraphDNS addresses this limitation by:

- taking **static authoritative configurations** as input
- constructing a **global resolution relation graph**
- removing semantically shadowed records via local priority rules
- deriving a **reachable-path view**
- verifying configuration errors under a unified semantic framework

This enables GraphDNS to cover not only traditional path vulnerabilities, but also structural anomalies such as:

- **orphan records**, which lose valid delegation support but remain reachable
- **shadow records**, which remain in the configuration but no longer participate in any legal resolution path

---

## Architecture

GraphDNS follows a two-stage architecture:

### 1. Preprocessing Stage (C++ Frontend)
Responsible for:

- zone-file parsing
- resource-record extraction
- fact generation
- input normalization and preprocessing

### 2. Verification Stage (Soufflé Backend)
Responsible for:

- constructing global resolution relations
- recursively deriving the reachable-path view
- evaluating error predicates
- producing verification outputs

---

## Repository Structure

```text
GraphDNS/
├── src/
│   ├── synthetic_dataset/     # Synthetic dataset
│   ├── dns_verify.dl          # Main Soufflé Datalog rules of GraphDNS
│   ├── main.cpp               # C++ frontend for zone parsing and fact generation
│   └── README.md              # Documentation for the src directory
├── test/
│   ├── dns_verify.dl          # Rule set used for evaluation
│   ├── main.cpp               # Frontend program for experiments
│   ├── run_experiments.sh     # Batch script for large-scale experiments
│   └── README.md              # Documentation for the test directory
└── README.md                  # Top-level project documentation
```

---

## Use Cases

GraphDNS is suitable for:

* offline auditing of large DNS configurations
* configuration pre-checking for DNS hosting providers
* academic experiments on formal DNS verification
* production problem mining in operational DNS environments
* security-oriented DNS consistency analysis

---

## Acknowledgments

We thank the providers of public DNS datasets, the Soufflé community, and the technical teams who supported the validation of this project on real-world configurations.
