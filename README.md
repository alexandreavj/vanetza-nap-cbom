# CBOM Benchmark for Vanetza

## Index

- [Objectives](#objectives)
- [What is Vanetza and why it was chosen](#what-is-vanetza-and-why-it-was-chosen)
- [Structure of the CBOM part](#structure-of-the-cbom-part)
- [Installation and run script](#installation-and-run-script)
- [Implemented tools](#implemented-tools)
  - [sonar-cryptography](#sonar-cryptography)

## Objectives

The goal of this project is to benchmark different tools that analyse a software system and generate its
Cryptography Bill of Materials (CBOM). All tools are run on the same target, Vanetza, and their results are compared.

The benchmark covers four kinds of tools:

- **Source analysis tools**, which read the source code.
- **Binary analysis tools**, which inspect compiled programs and libraries.
- **Syscall interception tools**, which observe the program while it runs.
- **LLM-assisted generation**, where a language model produces the CBOM from the code.

## What is Vanetza?

Vanetza is a C++ implementation of an ETSI C-ITS (V2X) stack, the communication software used by connected vehicles
and roadside units. This repository contains the Vanetza-NAP version of it.

It was chosen because:
- It is safety-critical. Vehicles and roadside units use Vanetza-style stacks to broadcast safety messages such as awareness and hazard warnings. Receivers must
  be able to trust where a message came from, so the cryptography directly affects road safety.
- Its security code signs and verifies messages with ECDSA (NIST P-256) and SHA-256, a small cryptographic surface
  that can be inventoried by hand and used as a reference.
- It has two interchangeable cryptographic backends, OpenSSL and Crypto++, selected at build time. A tool that only
  knows one library will miss the other.

## Structure of the CBOM part

The benchmark lives in the `cbom/` folder. Each tool has its own folder with a script that installs the tool and
runs its experiments.

```text
cbom/
  <tool>/
    run.py          installs the tool and runs the experiments
    README.md       notes on the tool
    results/
      <experiment>/cbom.json
    work/           downloads, builds and logs (not committed)
```

Every tool follows the same rules:

- The script is `run.py`, with the commands `all`, `setup` and `experiments`.
- Everything the script installs goes into `work/`, and nothing is written into the Vanetza source tree.
- Each experiment writes its CBOM to `results/<experiment>/cbom.json`.
- Versions are pinned, and no passwords or tokens are stored.

## Installation and run script

Each tool's script takes care of the installation and of running the experiments. For the implemented tool:

```bash
cd cbom/sonar-cryptography
chmod +x run.py
INSTALL_DEPS=1 ./run.py              # install everything, then run all experiments
./run.py setup                       # install only
./run.py experiments                 # experiments only
```

`INSTALL_DEPS=1` installs missing packages with `apt install`. Docker must already be installed.

## Implemented tools

### sonar-cryptography

#### Installation and run script breakdown

`cbom/sonar-cryptography/run.py`:

1. Checks the prerequisites and optionally installs the missing packages.
2. Clones the plugin, fetches pull request #377 (C/C++ support) and checks out a pinned commit.
3. Builds the plugin with Maven.
4. Starts SonarQube with Docker Compose and waits until it is ready.
5. Downloads the SonarScanner CLI for the machine's CPU.
6. Creates a C/C++ quality profile with the rule `sonar-cpp-crypto:Inventory`.
7. Runs each experiment and saves its `cbom.json`, the scanner settings and the scanner log.
8. Prints the evidence found by each experiment (component, file, line) and writes `results/evidence.csv` and
   `results/comparison.md`.

#### Why this tool?

- It is open source and developed in the CBOMkit project.
- It produces standard CycloneDX CBOMs with file and line evidence.
- Its C/C++ support (pull request #377) targets the kind of system used in this benchmark.

#### Experiments

The tool analyses C/C++ through a preprocessor, so the result can depend on the defines and on which files are
scanned. Each experiment tests one of these factors.

| Experiment | Files scanned | Defines | Why |
|---|---|---|---|
| E1-full-baseline | `vanetza/security`, `tools/certify`, `tools/socktap` | OpenSSL, Crypto++, `OPENSSL_API_COMPAT 0x10101000L` | Reference run with a realistic build configuration (OpenSSL 1.1.1, as in the Docker image). |
| E2-full-cryptopp-defines | same | Crypto++ only | Checks whether the preprocessor configuration changes the CBOM. |
| E3-cryptopp-files-only | Crypto++ files only | Crypto++ | Checks whether the plugin finds anything in the Crypto++ code. |
| E4-openssl-files-only | OpenSSL files only | OpenSSL, `0x10101000L` | Checks whether a narrow scan gives the same CBOM as the full one. |
| E5-openssl-files-legacy | OpenSSL files only | OpenSSL, `0x10000000L` | Checks whether `OPENSSL_API_COMPAT` (OpenSSL 1.0 versus 1.1 code paths) changes the result. |

#### Sources

- sonar-cryptography: <https://github.com/cbomkit/sonar-cryptography> (C/C++ support: pull request #377)
- SonarQube Community Build, started with Docker Compose from the plugin repository: <https://hub.docker.com/_/sonarqube>
- SonarScanner CLI 8.5.0.16571, from `binaries.sonarsource.com`
- CycloneDX CBOM: <https://cyclonedx.org/capabilities/cbom/>
