#!/usr/bin/env python3
"""
Automated bad-character finder for argv-based Linux overflow targets.

The documented workflow in README.md uses:

    run $(python3 -c '...')

That means the payload reaches the program through two layers:

1. The shell transport created by GDB's `run` command.
2. The target program's `argv[1]`.

Those layers have different bad-character behavior:

- `argv-direct`: measures what the target really accepts when launched via a
  raw `execve()`. For the example binary, only `\x00` is bad.
- `argv-shell`: reproduces the markdown workflow faithfully. The shell will
  treat `\x09`, `\x0a`, and `\x20` as field separators, so they show up as bad
  before the target ever sees them.

This script supports both modes and defaults to `argv-shell` so it matches the
process described in the markdown, while still allowing the direct mode when
you want to isolate the binary from shell artifacts.

Current scope:
- Linux ELF `i386` and `amd64`
- argv-based delivery only
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path

from pwn import ELF, context, log


@dataclass(frozen=True)
class ArchProfile:
    name: str
    bits: int
    overwrite_len: int
    arg_exprs: tuple[str, ...]


@dataclass(frozen=True)
class Mismatch:
    index: int
    expected: int
    observed: int | None
    reason: str


TRANSPORT_DIRECT = "argv-direct"
TRANSPORT_SHELL = "argv-shell"


def parse_escaped_bytes(value: str) -> bytes:
    """Convert a CLI string like '\\x41\\x42' into raw bytes."""
    try:
        return value.encode().decode("unicode_escape").encode("latin-1")
    except UnicodeDecodeError as exc:
        raise argparse.ArgumentTypeError(f"invalid escaped byte string: {value!r}") from exc


def load_arch_profile(binary: str) -> ArchProfile:
    elf = ELF(binary, checksec=False)

    if elf.arch == "i386" and elf.bits == 32:
        context.update(arch="i386", os="linux")
        return ArchProfile(
            name="i386",
            bits=32,
            overwrite_len=4,
            arg_exprs=(
                "*(char **)($ebp+8)",
                "*(char **)($esp+4)",
            ),
        )

    if elf.arch == "amd64" and elf.bits == 64:
        context.update(arch="amd64", os="linux")
        return ArchProfile(
            name="amd64",
            bits=64,
            overwrite_len=8,
            arg_exprs=(
                "(char *)$rdi",
            ),
        )

    raise ValueError(
        f"unsupported target architecture: arch={elf.arch!r}, bits={elf.bits}. "
        "Only Linux i386 and amd64 are supported right now."
    )


def build_payload(total_size: int, test_chars: bytes, overwrite_bytes: bytes, pad_byte: int) -> tuple[bytes, int]:
    pad_len = total_size - len(test_chars) - len(overwrite_bytes)
    if pad_len < 0:
        raise ValueError(
            "buffer size is too small for the remaining test chars plus the overwrite bytes"
        )
    payload = bytes([pad_byte]) * pad_len + test_chars + overwrite_bytes
    return payload, pad_len


def make_execve_wrapper(path: Path) -> None:
    path.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import os
            import sys

            binary = os.path.abspath(sys.argv[1]).encode()
            payload = open(sys.argv[2], "rb").read()
            os.execve(binary, [binary, payload], os.environ.copy())
            """
        ),
        encoding="ascii",
    )
    path.chmod(0o700)


def build_shell_run_command(payload_path: Path) -> str:
    py = os.path.abspath(sys.executable)
    payload_literal = repr(str(payload_path))
    return (
        f'run $({py} -c "import sys; '
        f'sys.stdout.buffer.write(open({payload_literal}, \\"rb\\").read())")'
    )


def run_gdb_dump(
    gdb_argv: list[str],
    breakpoint: str,
    arg_expr: str,
    read_len: int,
    dump_path: Path,
    script_path: Path,
    timeout: int,
    startup_with_shell: bool,
    run_command: str,
    shell_path: str | None,
) -> tuple[bytes | None, str]:
    dump_path.unlink(missing_ok=True)

    script_path.write_text(
        "\n".join(
            [
                "set pagination off",
                "set confirm off",
                "set breakpoint pending on",
                f"set startup-with-shell {'on' if startup_with_shell else 'off'}",
                "set follow-exec-mode same",
                "set disable-randomization on",
                "set print thread-events off",
                f"break {breakpoint}",
                run_command,
                f"set $arg = {arg_expr}",
                f"dump binary memory {dump_path} $arg $arg+{read_len}",
                "quit",
            ]
        )
        + "\n",
        encoding="ascii",
    )

    env = os.environ.copy()
    env.update({"LANG": "C", "LC_ALL": "C"})
    if shell_path is not None:
        env["SHELL"] = shell_path

    result = subprocess.run(
        gdb_argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )

    transcript = result.stdout
    if result.stderr:
        transcript += "\n" + result.stderr

    if dump_path.exists():
        return dump_path.read_bytes(), transcript

    return None, transcript


def capture_argument_bytes(
    binary: str,
    payload: bytes,
    breakpoint: str,
    profile: ArchProfile,
    timeout: int,
    transport: str,
    shell_path: str | None,
) -> tuple[bytes, str, str]:
    """Dump argv[1] directly from the first-argument pointer inside GDB."""

    read_len = len(payload) + 1

    with tempfile.TemporaryDirectory(prefix="badchars_") as tmpdir_name:
        tmpdir = Path(tmpdir_name)
        payload_path = tmpdir / "payload.bin"
        dump_path = tmpdir / "arg_dump.bin"
        script_path = tmpdir / "cmds.gdb"

        payload_path.write_bytes(payload)

        if transport == TRANSPORT_DIRECT:
            wrapper_path = tmpdir / "execve_wrapper.py"
            make_execve_wrapper(wrapper_path)
            gdb_argv = [
                "gdb",
                "-nx",
                "-q",
                "-batch",
                "-x",
                str(script_path),
                "--args",
                sys.executable,
                str(wrapper_path),
                os.path.abspath(binary),
                str(payload_path),
            ]
            startup_with_shell = False
            run_command = "run"
        elif transport == TRANSPORT_SHELL:
            gdb_argv = [
                "gdb",
                "-nx",
                "-q",
                "-batch",
                "-x",
                str(script_path),
                os.path.abspath(binary),
            ]
            startup_with_shell = True
            run_command = build_shell_run_command(payload_path)
        else:
            raise ValueError(f"unsupported transport mode: {transport}")

        transcripts: list[str] = []
        for arg_expr in profile.arg_exprs:
            observed, transcript = run_gdb_dump(
                gdb_argv=gdb_argv,
                breakpoint=breakpoint,
                arg_expr=arg_expr,
                read_len=read_len,
                dump_path=dump_path,
                script_path=script_path,
                timeout=timeout,
                startup_with_shell=startup_with_shell,
                run_command=run_command,
                shell_path=shell_path,
            )
            transcripts.append(f"[arg expr: {arg_expr}]\n{transcript.strip()}\n")
            if observed is not None:
                return observed, arg_expr, "\n".join(transcripts)

    raise RuntimeError(
        "GDB could not dump argv[1] from the breakpoint. "
        "Tried argument expressions: "
        + ", ".join(profile.arg_exprs)
        + "\n\n"
        + "\n".join(transcripts)
    )


def split_observed_argument(observed: bytes) -> bytes:
    """Return the actual argv string bytes up to the first terminating null."""
    terminator = observed.find(b"\x00")
    if terminator == -1:
        return observed
    return observed[:terminator]


def find_first_mismatch(expected: bytes, observed: bytes) -> Mismatch | None:
    """Return the earliest confirmed mismatch, conservatively, or None."""
    for index, exp in enumerate(expected):
        if index >= len(observed):
            return Mismatch(index=index, expected=exp, observed=None, reason="truncated")

        cur = observed[index]
        if cur == exp:
            continue

        next_exp = expected[index + 1] if index + 1 < len(expected) else None
        next_obs = observed[index + 1] if index + 1 < len(observed) else None

        if next_exp is not None and cur == next_exp:
            return Mismatch(index=index, expected=exp, observed=cur, reason="dropped_or_shifted")

        if next_exp is not None and next_obs == next_exp:
            return Mismatch(index=index, expected=exp, observed=cur, reason="replaced")

        return Mismatch(index=index, expected=exp, observed=cur, reason="mismatch")

    return None


def sanity_check_padding(observed_arg: bytes, pad_len: int, pad_byte: int) -> None:
    prefix = observed_arg[:pad_len]
    if len(prefix) < pad_len:
        raise RuntimeError(
            "the observed argv string ended before the CHARS region. "
            "This usually means the padding byte was not delivered intact or the input was truncated early."
        )

    expected_prefix = bytes([pad_byte]) * pad_len
    if prefix != expected_prefix:
        mismatch_at = next(
            (idx for idx, (a, b) in enumerate(zip(prefix, expected_prefix)) if a != b),
            None,
        )
        raise RuntimeError(
            "the padding region did not arrive intact. "
            f"First mismatch at offset {mismatch_at}: observed=0x{prefix[mismatch_at]:02x}, "
            f"expected=0x{pad_byte:02x}. Pick a different --pad-byte or inspect the transport."
        )


def find_all_bad_chars(
    binary: str,
    total_size: int,
    breakpoint: str,
    profile: ArchProfile,
    overwrite_bytes: bytes,
    pad_byte: int,
    max_rounds: int,
    timeout: int,
    transport: str,
    shell_path: str | None,
) -> list[int]:
    """Iteratively discover bad characters for argv[1] delivery."""
    bad_chars: list[int] = [0x00]
    log.info("argv delivery selected: treating 0x00 as bad by definition")

    for round_num in range(1, max_rounds + 1):
        test_chars = bytes(b for b in range(0x01, 0x100) if b not in bad_chars)
        if not test_chars:
            log.success("No test characters remain")
            break

        payload, pad_len = build_payload(total_size, test_chars, overwrite_bytes, pad_byte)
        log.info(
            f"Round {round_num}: testing {len(test_chars)} chars, pad_len={pad_len}, "
            f"known bad={','.join(f'0x{b:02x}' for b in bad_chars)}"
        )

        observed_bytes, arg_expr, transcript = capture_argument_bytes(
            binary=binary,
            payload=payload,
            breakpoint=breakpoint,
            profile=profile,
            timeout=timeout,
            transport=transport,
            shell_path=shell_path,
        )
        observed_arg = split_observed_argument(observed_bytes)

        log.info(
            f"  GDB arg expression: {arg_expr} | observed argv[1] length: {len(observed_arg)}"
        )

        sanity_check_padding(observed_arg, pad_len, pad_byte)
        observed_chars = observed_arg[pad_len : pad_len + len(test_chars)]
        mismatch = find_first_mismatch(test_chars, observed_chars)

        if mismatch is None:
            log.success("Clean pass: all remaining non-null bytes arrived intact")
            break

        if mismatch.expected in bad_chars:
            raise RuntimeError(
                f"detected an already-known bad char again at offset {mismatch.index}: "
                f"0x{mismatch.expected:02x}"
            )

        bad_chars.append(mismatch.expected)
        observed_desc = "missing" if mismatch.observed is None else f"0x{mismatch.observed:02x}"
        log.warning(
            "  first mismatch in CHARS region at index "
            f"{mismatch.index}: expected=0x{mismatch.expected:02x}, observed={observed_desc}, "
            f"reason={mismatch.reason}"
        )
        log.debug(transcript)

    return sorted(bad_chars)


def print_results(bad_chars: list[int]) -> None:
    """Display the final results in useful exploit-dev formats."""
    print("\n" + "=" * 60)
    print("  BAD CHARACTER DETECTION - RESULTS")
    print("=" * 60)

    print(f"\n  Total bad characters found: {len(bad_chars)}\n")

    names = {
        0x00: "Null byte / argv terminator",
        0x09: "Horizontal tab",
        0x0A: "Line feed (\\n)",
        0x0D: "Carriage return (\\r)",
        0x20: "Space",
        0xFF: "0xFF",
    }
    print(f"  {'Hex':<8} {'Dec':<6} {'Description'}")
    print(f"  {'---':<8} {'---':<6} {'-----------'}")
    for b in bad_chars:
        print(f"  0x{b:02x}     {b:<6} {names.get(b, '')}")

    hex_str = "".join(f"\\x{b:02x}" for b in bad_chars)
    print("\n  For msfvenom -b flag:")
    print(f"    -b '{hex_str}'")

    print("\n  Python bytes:")
    print(f'    bad_chars = b"{hex_str}"')

    clean_count = 256 - len(bad_chars)
    print(f"\n  Clean characters remaining: {clean_count} / 256")
    print("=" * 60 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated bad-character finder for argv-based Linux ELF targets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:

  python3 %(prog)s ./bow32 1040 bowfunc
  python3 %(prog)s ./bow32 1040 bowfunc --pad-byte '\\x55' --overwrite '\\x66\\x66\\x66\\x66'
""",
    )
    parser.add_argument("binary", help="Path to the vulnerable binary")
    parser.add_argument("total_size", type=int, help="Total size to the saved return pointer")
    parser.add_argument("breakpoint", help="Breakpoint location, usually the vulnerable function name")
    parser.add_argument(
        "--transport",
        choices=(TRANSPORT_SHELL, TRANSPORT_DIRECT),
        default=TRANSPORT_SHELL,
        help=(
            "Delivery model to test. "
            "'argv-shell' reproduces `run $(python3 -c ...)` from the markdown. "
            "'argv-direct' launches via execve() and isolates the target from shell parsing. "
            f"Default: {TRANSPORT_SHELL}"
        ),
    )
    parser.add_argument(
        "--overwrite",
        type=parse_escaped_bytes,
        default=None,
        help="Overwrite marker bytes appended after CHARS. Defaults to 0x66 repeated for the target pointer width.",
    )
    parser.add_argument(
        "--pad-byte",
        type=parse_escaped_bytes,
        default=b"\x55",
        help="Single byte used for the padding region (default: \\x55)",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=255,
        help="Maximum iterative rounds before aborting (default: 255)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-round GDB timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--shell",
        default=None,
        help=(
            "Shell to use for --transport argv-shell. "
            "Defaults to /bin/bash when present, otherwise /bin/sh."
        ),
    )

    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        log.error(f"binary not found: {args.binary}")
        sys.exit(1)

    if len(args.pad_byte) != 1:
        log.error("--pad-byte must decode to exactly one byte")
        sys.exit(1)

    try:
        profile = load_arch_profile(args.binary)
    except ValueError as exc:
        log.error(str(exc))
        sys.exit(1)

    overwrite_bytes = args.overwrite if args.overwrite is not None else b"\x66" * profile.overwrite_len
    if not overwrite_bytes:
        log.error("--overwrite must not be empty")
        sys.exit(1)

    shell_path = None
    if args.transport == TRANSPORT_SHELL:
        shell_path = args.shell
        if shell_path is None:
            shell_path = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
        if not os.path.exists(shell_path):
            log.error(f"shell not found: {shell_path}")
            sys.exit(1)

    log.info(f"Target binary : {args.binary}")
    log.info(f"Architecture  : {profile.name} ({profile.bits}-bit)")
    log.info(f"Buffer size   : {args.total_size}")
    log.info(f"Breakpoint    : {args.breakpoint}")
    log.info(f"Transport     : {args.transport}")
    if shell_path is not None:
        log.info(f"Shell         : {shell_path}")
    log.info(f"Pad byte      : 0x{args.pad_byte[0]:02x}")
    log.info(f"Overwrite len : {len(overwrite_bytes)} bytes ({overwrite_bytes.hex()})")
    log.info("")

    try:
        bad_chars = find_all_bad_chars(
            binary=args.binary,
            total_size=args.total_size,
            breakpoint=args.breakpoint,
            profile=profile,
            overwrite_bytes=overwrite_bytes,
            pad_byte=args.pad_byte[0],
            max_rounds=args.max_rounds,
            timeout=args.timeout,
            transport=args.transport,
            shell_path=shell_path,
        )
    except (RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
        log.error(str(exc))
        sys.exit(1)

    print_results(bad_chars)


if __name__ == "__main__":
    main()
