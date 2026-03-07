# PyInstaller Source Recovery - Technical Notes (Python 3.14rc3)

## 1) Scope
This document describes the code and behavior of the PyInstaller recovery toolchain in this project:
- `pyinstaller_314_recovery/pyinstaller_314_recovery_pipeline.sh`
- `pyinstaller_314_recovery/pyinstaller_314_recovery_clean_main.py`

It focuses on implementation logic, patch behavior, and generated outputs.

---

## 2) Components

### 2.1 Pipeline script
`pyinstaller_314_recovery_pipeline.sh` is the orchestrator. It:
- validates arguments (`<pyc_dir> [output_dir]`),
- resolves helper paths relative to script location,
- prepares `cmake` (system binary or local venv fallback),
- clones and checks out `pycdc` PR #566,
- applies a Python 3.14rc3 compatibility patch set,
- builds `pycdc`,
- decompiles all `.pyc` files found under the input directory,
- selects a likely main module from generated outputs,
- generates `main_raw.py` and `main_clean.py`,
- writes `summary.txt`.

### 2.2 Main cleanup helper
`pyinstaller_314_recovery_clean_main.py` normalizes noisy decompiler output for the main module. It:
- parses key assignments from raw output using regex,
- rebuilds a readable template when required keys are present,
- falls back to the original raw content when extraction is incomplete.

---

## 3) Pipeline flow

1. Input validation
- Ensure input directory exists.
- Ensure helper script exists.

2. Toolchain setup
- Use `cmake` from PATH when available.
- Otherwise create/use a local virtual environment and install `cmake`.

3. `pycdc` source and patching
- Clone `zrax/pycdc` into `/tmp/pycdc314-work/pycdc-src` if missing.
- Checkout PR branch: `pull/566/head:pr-566`.
- Apply in-place compatibility patches for Python 3.14rc3.

4. Build
- Configure via CMake and compile `pycdc`.
- Validate resulting binary exists at `/tmp/pycdc314-work/pycdc-build/pycdc`.

5. Decompilation pass
- Discover all `.pyc` files recursively in input directory.
- Emit raw output to `<output_dir>/raw/**/*.py`.
- Emit stderr logs to `<output_dir>/errors/**/*.err`.

6. Main module selection
- Choose largest non-runtime candidate (`pyi_*`, `pyimod*`, `struct.py` filtered).
- If none match, fallback to first available `.py` output.

7. Post-processing
- Copy selected main file to `<output_dir>/main_raw.py`.
- Run helper to generate `<output_dir>/main_clean.py`.

8. Summary generation
- Write input/output metadata and error counts to `<output_dir>/summary.txt`.

---

## 4) Python 3.14rc3 compatibility patch set

Patches are applied directly to checked-out `pycdc` source.

### 4.1 Magic number update (`pyc_module.h`)
- Update `MAGIC_3_14` from `0x0A0D0E29` to `0x0A0D0E2B`.
- Purpose: accept 3.14rc3 bytecode magic (`2b0e0d0a` LE).

### 4.2 Opcode remapping (`bytes/python_3_14.cpp`)
- `LOAD_FAST_BORROW` -> `LOAD_FAST_A`
- `LOAD_FAST_BORROW_LOAD_FAST_BORROW` -> `LOAD_FAST_LOAD_FAST_A`
- `FOR_ITER_GEN` -> `FOR_ITER_A`
- Purpose: reuse semantically close handlers for specialized opcodes.

### 4.3 `BINARY_OP_A` operand 26 (`ASTree.cpp`)
- Treat operand `26` as subscription (`ASTSubscr`) instead of generic binary op.
- Purpose: preserve `obj[idx]` forms.

### 4.4 `MAKE_FUNCTION` no-arg case (`ASTree.cpp`)
- Add `case Pyc::MAKE_FUNCTION:` with `operand = 0` and fallthrough.
- Purpose: handle 3.14 stream variants.

### 4.5 Additional opcode handling (`ASTree.cpp`)
- `LOAD_FAST_AND_CLEAR_A`
- `LOAD_SMALL_INT_A`
- `STORE_FAST_LOAD_FAST_A`
- Purpose: restore stack/local behavior for fused/new opcodes.

### 4.6 `CALL` sentinel robustness (`ASTree.cpp`)
- Defensive handling of null sentinel in 3.11+ calling convention.
- Purpose: avoid malformed call reconstruction (`None(...)` patterns).

### 4.7 Structural/format opcodes (`ASTree.cpp`)
- `NOT_TAKEN`, `PUSH_EXC_INFO`, `POP_ITER`, `RERAISE(_A)`, `FORMAT_SIMPLE`, `FORMAT_WITH_SPEC`.
- Purpose: prevent early aborts on non-core but valid stream operations.

---

## 5) Helper script behavior

The helper expects two paths:
- `raw_main`: raw decompiled main module
- `clean_main`: destination path

Processing logic:
- Extract constants:
  - `SECURE_CONFIG_BLOB`
  - `CDN_EDGE_NODE`
  - `UPDATE_ENDPOINT`
  - `PRIMARY_C2_ADDR`
  - `PRIMARY_C2_PORT`
- If all required keys are present, emit normalized template output.
- Otherwise, write original raw source unchanged.

This keeps the pipeline resilient: it never fails solely because template reconstruction is incomplete.

---

## 6) Output contract

For output directory `<output_dir>`:
- `<output_dir>/raw/*.py` (recursive): decompiled files
- `<output_dir>/errors/*.err` (recursive): decompilation stderr per file
- `<output_dir>/main_raw.py`: selected main-module raw output
- `<output_dir>/main_clean.py`: normalized or fallback-clean output
- `<output_dir>/summary.txt`: execution metadata and error counts

---

## 7) Usage

From repo root:

```bash
./pyinstaller_314_recovery/pyinstaller_314_recovery_pipeline.sh <pyc_dir> [output_dir]
```

Help:

```bash
./pyinstaller_314_recovery/pyinstaller_314_recovery_pipeline.sh --help
```

---

## 8) Limitations

- Main-module prioritization is heuristic (size + filename filters).
- Patch set is targeted to this Python 3.14rc3 profile and may require updates for:
  - other 3.14 builds,
  - upstream `pycdc` changes,
  - heavily obfuscated samples.
- The cleaner is schema-based (key extraction + template), not a generic AST rewriter.
