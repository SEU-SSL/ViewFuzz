# ViewFuzz

**Small is Enough: Collision-free and high-throughput greybox fuzzing with a fixed map size**

This repository is the official implementation of the paper:

> Yujian Zhang, Gelin Zhang, Jinyu Xu, Tong Su.
> *Small is Enough: Collision-free and high-throughput greybox fuzzing with a fixed map size.*
> Journal of Systems and Software, Volume 244, February 2027, 113126.
> DOI: [10.1016/j.jss.2026.113126](https://doi.org/10.1016/j.jss.2026.113126)

---

## Overview

ViewFuzz is a coverage-guided greybox fuzzer that achieves collision-free coverage tracking with a fixed bitmap size. It consists of three core components:

- **CA** (Coverage-tracing Augmentation): hashmap-based global collision tracking via static analysis and asynchronous coverage tracing
- **VNS** (Variable Neighborhood Search): multi-view scheduling via a VNS-based binary-switching strategy
- **HT** (High Throughput): compact bitmap + lightweight instrumentation

The workflow consists of two stages:

1. **Static compilation and analysis**: compile the target with `afl-clang-fast`, convert shared memory data to a binary file with `shmtofile`, and perform static analysis with `analysis_test`.
2. **Dynamic fuzzing**: run `afl-fuzz` with a shared memory ID, and dynamically augment the hashmap with `assist_addedges`.

---

## Requirements

- Linux (Ubuntu 20.04 or later recommended)
- `cmake >= 3.15`
- `make`
- `libpcap-dev` (for tcpdump)
- Target programs to fuzz (not included in this repository; see "Prepare a target" below)

---

## Compile

Compile ViewFuzz:

```bash
make clean
make
```

After compilation, the following binaries will be available in the repository root:

- `afl-clang-fast` / `afl-clang-fast++`: instrumented compilers
- `afl-fuzz`: the fuzzer
- `shmtofile`: converts shared memory data to a binary file
- `analysis_test`: static analysis tool
- `assist_addedges`: dynamic hashmap augmentation tool

---

## Prepare a target

This repository does **not** include benchmark programs or seed inputs. You need to prepare your own target program and seed inputs.

For a target program, compile it with the instrumented compilers:

```bash
cd /path/to/your/target
CC=/path/to/ViewFuzz/afl-clang-fast CXX=/path/to/ViewFuzz/afl-clang-fast++ ./configure
make -j8
```

Then run static analysis in a dedicated directory:

```bash
mkdir fuzz && cd fuzz
/path/to/ViewFuzz/shmtofile && \
/path/to/ViewFuzz/analysis_test /path/to/your/target/your_program
```

Prepare seed inputs:

```bash
mkdir -p /path/to/seeds
# Put your seed files into /path/to/seeds
```

---

## Run

Minimal example for a single target:

```bash
/path/to/ViewFuzz/afl-fuzz \
  -i /path/to/seeds \
  -o /path/to/output \
  -b <cpu_id> \
  -H <shm_id> \
  -d /path/to/your/target/your_program @@
```

**Key parameters**:

- `-i`: seed directory
- `-o`: output directory
- `-b`: CPU core to bind
- `-H`: shared memory ID (must be unique per program)
- `-d`: target binary
- `@@`: input file placeholder

After 10 seconds, launch dynamic hashmap augmentation:

```bash
/path/to/ViewFuzz/assist_addedges \
  -o ass_0 \
  -s <shm_id> \
  -q /path/to/output/default/queue \
  -c your_program \
  /path/to/output/default/your_program.predecessor @@
```

**Key parameters**:

- `-o`: output directory for `assist_addedges`
- `-s`: shared memory ID (must match the fuzzer's `-H`)
- `-q`: queue directory produced by the fuzzer
- `-c`: target program name

---

Additional examples can be found in `compile.sh` and `fuzz.sh`.

---


