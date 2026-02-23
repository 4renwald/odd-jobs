#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/pyinstaller_314_recovery/pyinstaller_314_recovery_pipeline.sh <pyc_dir> [output_dir]

What it does:
  1) Clone pycdc PR #566, patch for Python 3.14rc3, and build it.
  2) Decompile all .pyc files from <pyc_dir>.
  3) Generate a cleaned main source file from the decompiled main module.

Outputs:
  <output_dir>/raw/*.py
  <output_dir>/errors/*.err
  <output_dir>/main_raw.py
  <output_dir>/main_clean.py
  <output_dir>/summary.txt
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HELPER_PY="$SCRIPT_DIR/pyinstaller_314_recovery_clean_main.py"

INPUT_DIR="$1"
OUTPUT_DIR="${2:-recovered_min}"

if [[ ! -d "$INPUT_DIR" ]]; then
  echo "[!] Input directory not found: $INPUT_DIR"
  exit 1
fi

if [[ ! -f "$HELPER_PY" ]]; then
  echo "[!] Missing helper: $HELPER_PY"
  exit 1
fi

WORK_BASE="/tmp/pycdc314-work"
SRC_DIR="$WORK_BASE/pycdc-src"
BUILD_DIR="$WORK_BASE/pycdc-build"
VENV_DIR="$WORK_BASE/venv-tools"
PYCDC_BIN="$BUILD_DIR/pycdc"

RAW_DIR="$OUTPUT_DIR/raw"
ERR_DIR="$OUTPUT_DIR/errors"
mkdir -p "$RAW_DIR" "$ERR_DIR"

if command -v cmake >/dev/null 2>&1; then
  CMAKE_BIN="$(command -v cmake)"
else
  echo "[*] cmake not found in PATH; installing local tool venv in $VENV_DIR"
  if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
  fi
  "$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
  "$VENV_DIR/bin/python" -m pip install cmake >/dev/null
  CMAKE_BIN="$VENV_DIR/bin/cmake"
fi

if [[ ! -d "$SRC_DIR/.git" ]]; then
  echo "[*] Cloning pycdc source into $SRC_DIR"
  rm -rf "$SRC_DIR"
  git clone https://github.com/zrax/pycdc.git "$SRC_DIR"
fi

echo "[*] Checking out pycdc PR #566"
git -C "$SRC_DIR" fetch origin pull/566/head:pr-566
git -C "$SRC_DIR" checkout -f pr-566

echo "[*] Applying compatibility patch set for Python 3.14rc3"
SRC_DIR="$SRC_DIR" python3 - <<'PY'
import os
import pathlib
import re
import sys

src = pathlib.Path(os.environ["SRC_DIR"])


def replace_once(path: pathlib.Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"Patch anchor not found in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# pyc_module.h: accept 3.14rc3 magic (2b0e0d0a => little-endian 0x0A0D0E2B)
pyc_module_h = src / "pyc_module.h"
text = pyc_module_h.read_text(encoding="utf-8")
if "MAGIC_3_14 = 0x0A0D0E2B," not in text:
    text = text.replace("MAGIC_3_14 = 0x0A0D0E29,", "MAGIC_3_14 = 0x0A0D0E2B,")
    pyc_module_h.write_text(text, encoding="utf-8")

# bytes/python_3_14.cpp: map a few specialized opcodes to existing handlers.
map_314 = src / "bytes/python_3_14.cpp"
text = map_314.read_text(encoding="utf-8")
text = text.replace("MAP_OP(86, LOAD_FAST_BORROW)", "MAP_OP(86, LOAD_FAST_A)")
text = text.replace(
    "MAP_OP(87, LOAD_FAST_BORROW_LOAD_FAST_BORROW)",
    "MAP_OP(87, LOAD_FAST_LOAD_FAST_A)",
)
text = text.replace("MAP_OP(171, FOR_ITER_GEN)", "MAP_OP(171, FOR_ITER_A)")
map_314.write_text(text, encoding="utf-8")

ast = src / "ASTree.cpp"

# BINARY_OP operand 26 => subscription, not arithmetic.
replace_once(
    ast,
    """        case Pyc::BINARY_OP_A:
            {
                ASTBinary::BinOp op = ASTBinary::from_binary_op(operand);
                if (op == ASTBinary::BIN_INVALID)
                    fprintf(stderr, "Unsupported `BINARY_OP` operand value: %d\\n", operand);
                PycRef<ASTNode> right = stack.top();
                stack.pop();
                PycRef<ASTNode> left = stack.top();
                stack.pop();
                stack.push(new ASTBinary(left, right, op));
            }
            break;
""",
    """        case Pyc::BINARY_OP_A:
            {
                PycRef<ASTNode> right = stack.top();
                stack.pop();
                PycRef<ASTNode> left = stack.top();
                stack.pop();
                if (operand == 26) {
                    // Python 3.14: BINARY_OP operand for obj[idx].
                    stack.push(new ASTSubscr(left, right));
                } else {
                    ASTBinary::BinOp op = ASTBinary::from_binary_op(operand);
                    if (op == ASTBinary::BIN_INVALID)
                        fprintf(stderr, "Unsupported `BINARY_OP` operand value: %d\\n", operand);
                    stack.push(new ASTBinary(left, right, op));
                }
            }
            break;
""",
)

# Support MAKE_FUNCTION without arg in 3.14.
replace_once(
    ast,
    """        case Pyc::MAKE_CLOSURE_A:
        case Pyc::MAKE_FUNCTION_A:
            {
""",
    """        case Pyc::MAKE_FUNCTION:
            operand = 0;
            [[fallthrough]];
        case Pyc::MAKE_CLOSURE_A:
        case Pyc::MAKE_FUNCTION_A:
            {
""",
)

# Handle LOAD_FAST_AND_CLEAR and LOAD_SMALL_INT.
replace_once(
    ast,
    """        case Pyc::LOAD_FAST_A:
            if (mod->verCompare(1, 3) < 0)
                stack.push(new ASTName(code->getName(operand)));
            else
                stack.push(new ASTName(code->getLocal(operand)));
            break;
""",
    """        case Pyc::LOAD_FAST_A:
            if (mod->verCompare(1, 3) < 0)
                stack.push(new ASTName(code->getName(operand)));
            else
                stack.push(new ASTName(code->getLocal(operand)));
            break;
        case Pyc::LOAD_FAST_AND_CLEAR_A:
            stack.push(new ASTName(code->getLocal(operand)));
            break;
        case Pyc::LOAD_SMALL_INT_A:
            stack.push(new ASTObject(new PycInt(operand)));
            break;
""",
)

# Handle STORE_FAST_LOAD_FAST.
replace_once(
    ast,
    """        case Pyc::STORE_GLOBAL_A:
            {
""",
    """        case Pyc::STORE_FAST_LOAD_FAST_A:
            {
                PycRef<ASTNode> value = stack.top();
                stack.pop();
                int store_idx = (operand >> 4) & 0xF;
                int load_idx = operand & 0xF;
                curblock->append(new ASTStore(value, new ASTName(code->getLocal(store_idx))));
                stack.push(new ASTName(code->getLocal(load_idx)));
            }
            break;
        case Pyc::STORE_GLOBAL_A:
            {
""",
)

# Robust CALL handling around NULL sentinels.
replace_once(
    ast,
    """                if ((opcode == Pyc::CALL_A || opcode == Pyc::INSTRUMENTED_CALL_A) &&
                        stack.top() == nullptr) {
                    stack.pop();
                }
""",
    """                if ((opcode == Pyc::CALL_A || opcode == Pyc::INSTRUMENTED_CALL_A) &&
                        !stack.empty()) {
                    if (func == nullptr && !stack.empty()) {
                        func = stack.top();
                        stack.pop();
                    }
                    if (!stack.empty() && stack.top() == nullptr) {
                        stack.pop();
                    }
                }
""",
)

# No-op / formatting helpers for 3.14 stream noise.
replace_once(
    ast,
    """        case Pyc::PUSH_NULL:
            stack.push(nullptr);
            break;
""",
    """        case Pyc::NOT_TAKEN:
            break;
        case Pyc::PUSH_EXC_INFO:
            break;
        case Pyc::POP_ITER:
            if (!stack.empty())
                stack.pop();
            break;
        case Pyc::RERAISE:
        case Pyc::RERAISE_A:
            break;
        case Pyc::FORMAT_SIMPLE:
            {
                PycRef<ASTNode> val = stack.top();
                stack.pop();
                stack.push(new ASTFormattedValue(val, ASTFormattedValue::NONE, nullptr));
            }
            break;
        case Pyc::FORMAT_WITH_SPEC:
            {
                PycRef<ASTNode> fmt = stack.top();
                stack.pop();
                PycRef<ASTNode> val = stack.top();
                stack.pop();
                auto flag = static_cast<ASTFormattedValue::ConversionFlag>(ASTFormattedValue::HAVE_FMT_SPEC);
                stack.push(new ASTFormattedValue(val, flag, fmt));
            }
            break;
        case Pyc::PUSH_NULL:
            stack.push(nullptr);
            break;
""",
)
PY

echo "[*] Building patched pycdc"
"$CMAKE_BIN" -S "$SRC_DIR" -B "$BUILD_DIR" >/dev/null
"$CMAKE_BIN" --build "$BUILD_DIR" -j >/dev/null

if [[ ! -x "$PYCDC_BIN" ]]; then
  echo "[!] pycdc build failed: $PYCDC_BIN not found"
  exit 1
fi

echo "[*] Decompiling .pyc files"
mapfile -t PYC_FILES < <(find "$INPUT_DIR" -type f -name '*.pyc' | sort)
if [[ ${#PYC_FILES[@]} -eq 0 ]]; then
  echo "[!] No .pyc files found in $INPUT_DIR"
  exit 1
fi

for pyc in "${PYC_FILES[@]}"; do
  rel="${pyc#"$INPUT_DIR"/}"
  raw_out="$RAW_DIR/${rel%.pyc}.py"
  err_out="$ERR_DIR/${rel%.pyc}.err"
  mkdir -p "$(dirname "$raw_out")" "$(dirname "$err_out")"
  "$PYCDC_BIN" "$pyc" >"$raw_out" 2>"$err_out" || true
done

MAIN_RAW="$(
  RAW_DIR="$RAW_DIR" python3 - <<'PY'
import os
import pathlib

raw_dir = pathlib.Path(os.environ["RAW_DIR"])
candidates = []
for p in raw_dir.rglob("*.py"):
    name = p.name.lower()
    if name.startswith("pyi_") or name.startswith("pyimod") or name == "struct.py":
        continue
    size = p.stat().st_size
    candidates.append((size, p))

if not candidates:
    all_py = sorted(raw_dir.rglob("*.py"))
    print(all_py[0] if all_py else "")
else:
    print(max(candidates, key=lambda x: x[0])[1])
PY
)"

if [[ -z "$MAIN_RAW" || ! -f "$MAIN_RAW" ]]; then
  echo "[!] Unable to determine main decompiled file."
  exit 1
fi

cp "$MAIN_RAW" "$OUTPUT_DIR/main_raw.py"
python3 "$HELPER_PY" "$MAIN_RAW" "$OUTPUT_DIR/main_clean.py"

TOTAL_ERRS=$(find "$ERR_DIR" -type f -name '*.err' | wc -l | tr -d ' ')
NONEMPTY_ERRS=$(find "$ERR_DIR" -type f -name '*.err' -size +0c | wc -l | tr -d ' ')

{
  echo "Input directory: $INPUT_DIR"
  echo "Output directory: $OUTPUT_DIR"
  echo "pycdc source: $SRC_DIR (branch pr-566 patched)"
  echo "Main raw file: $OUTPUT_DIR/main_raw.py"
  echo "Main cleaned file: $OUTPUT_DIR/main_clean.py"
  echo "Error logs: $ERR_DIR"
  echo "Error files total: $TOTAL_ERRS"
  echo "Error files non-empty: $NONEMPTY_ERRS"
} > "$OUTPUT_DIR/summary.txt"

echo "[+] Done."
echo "    - Raw decompilation: $OUTPUT_DIR/main_raw.py"
echo "    - Cleaned source:    $OUTPUT_DIR/main_clean.py"
echo "    - Summary:           $OUTPUT_DIR/summary.txt"
