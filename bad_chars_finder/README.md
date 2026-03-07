# `bad_chars_finder.py` Guide

## Purpose

`bad_chars_finder.py` automates iterative bad-character discovery for Linux ELF
targets that receive attacker-controlled data in `argv[1]`.

The script:

1. Builds a payload made of padding, a candidate byte set, and an overwrite marker.
2. Launches the target under GDB.
3. Breaks at a location you choose.
4. Reads the first argument directly from memory.
5. Compares the observed bytes with the bytes that were meant to arrive.
6. Removes the earliest confirmed bad byte and repeats until the remaining set is clean.


## Requirements

- Linux
- Python 3
- `gdb`
- `pwntools`
- A target ELF binary built for `i386` or `amd64`
- A known offset from the start of `argv[1]` to the saved return pointer or other overwrite location
- A reliable breakpoint location before the vulnerable copy has fully destroyed the state you want to inspect


## Supported Delivery Models

The script supports two transport modes because the delivery path changes which
bytes are actually bad.

### `argv-shell`

This is the default mode.

Use it when your workflow sends the payload through a shell-backed `run`
command inside GDB. In this mode, shell parsing can remove or split bytes before
the target ever receives them.

### `argv-direct`

Use this mode when you want to test the target's `argv[1]` handling without
shell parsing. The script launches the target with `execve()` so every non-null
byte is passed directly as an argument.

### Choosing the Right Mode

- Pick `argv-shell` when you want to reproduce a shell-mediated GDB workflow.
- Pick `argv-direct` when you want the result to reflect only the target's argv handling.


## Basic Usage

From repo root:

```bash
python3 ./bad_chars_finder/bad_chars_finder.py <binary> <total_size> <breakpoint>
```

Example:

```bash
python3 ./bad_chars_finder/bad_chars_finder.py ./target_binary 1040 vulnerable_function
```


## Arguments

### Positional Arguments

- `binary`: path to the target ELF
- `total_size`: total number of bytes needed to reach the overwrite location
- `breakpoint`: function name, symbol, or GDB breakpoint expression

### Optional Arguments

- `--transport {argv-shell,argv-direct}`
  Selects the delivery model. Default: `argv-shell`

- `--overwrite '<escaped_bytes>'`
  Marker bytes appended after the test byte set. If omitted, the script uses
  `\x66` repeated to the target pointer width.

- `--pad-byte '<escaped_byte>'`
  Single-byte filler used before the test bytes. Default: `\x55`

- `--max-rounds <n>`
  Maximum number of discovery rounds. Default: `255`

- `--timeout <seconds>`
  Per-round GDB timeout. Default: `30`

- `--shell <path>`
  Shell used for `argv-shell`. If omitted, the script prefers `/bin/bash` and
  falls back to `/bin/sh`.


## Common Commands

Run with the default shell-backed transport:

```bash
python3 ./bad_chars_finder/bad_chars_finder.py ./target_binary 1040 vulnerable_function
```

Run without shell parsing:

```bash
python3 ./bad_chars_finder/bad_chars_finder.py ./target_binary 1040 vulnerable_function --transport argv-direct
```

Use a custom overwrite marker:

```bash
python3 ./bad_chars_finder/bad_chars_finder.py ./target_binary 1040 vulnerable_function --overwrite '\x42\x42\x42\x42'
```

Use a different padding byte:

```bash
python3 ./bad_chars_finder/bad_chars_finder.py ./target_binary 1040 vulnerable_function --pad-byte '\x41'
```


## How to Choose `total_size`

`total_size` is the full distance from the beginning of `argv[1]` to the
overwrite location you are targeting.

Typical ways to determine it:

- a cyclic pattern and crash analysis
- a known offset from a previous exploit-development step
- source review if the layout is trivial and reliable

If `total_size` is too small, the script will stop because the payload cannot
fit the current test set plus the overwrite marker.


## How to Choose a Breakpoint

The breakpoint should stop execution while the original argument is still
available and before the relevant memory state is lost.

Good candidates:

- the vulnerable function entry
- the instruction immediately before a copy operation
- a location after input has been received but before the process crashes

If the breakpoint is too late, the argument may already be modified or gone.


## Output

The script prints:

- the target architecture
- the selected transport mode
- the per-round test size
- the first mismatch detected in each round
- the final bad-character list
- a ready-to-use `msfvenom -b` string
- a Python bytes literal

Example result format:

```text
Total bad characters found: 4

0x00
0x09
0x0a
0x20
```


## Interpreting Results

- `0x00` is always bad for argv delivery because argv strings are null-terminated.
- A byte found in `argv-shell` may be caused by shell parsing rather than the target itself.
- A byte found in `argv-direct` is much more likely to reflect the target's true argv handling.

If the results differ between the two modes, the transport path is affecting the payload.


## Troubleshooting

### The script says the padding region did not arrive intact

Possible causes:

- the padding byte is unsafe for the selected transport
- the breakpoint is wrong
- the payload is not reaching the process the way you expect

Try:

- changing `--pad-byte`
- switching between `argv-shell` and `argv-direct`
- verifying the breakpoint manually in GDB

### The script cannot dump `argv[1]`

Possible causes:

- the breakpoint is not hit
- the selected breakpoint is not inside a frame where the first argument can be recovered
- the target architecture is unsupported

Try:

- checking the symbol name
- using a different breakpoint expression
- confirming the binary is `i386` or `amd64`

### The script reports only `0x00`

That usually means the selected transport allows all other tested bytes to
reach the target intact.

### The script reports extra bad characters in `argv-shell`

That usually means the shell is splitting or transforming bytes before the
target sees them.


## Limitations

- Only Linux ELF `i386` and `amd64` are supported
- Only `argv[1]` delivery is supported
- The script does not currently test `stdin`, files, sockets, or environment-variable delivery
- Results are only as good as the chosen breakpoint and offset


## Recommended Workflow

1. Determine the overwrite offset first.
2. Start with `argv-shell` if your manual process uses a shell-backed GDB launch.
3. Re-run with `argv-direct` if you want to separate shell effects from target effects.
4. Validate the final bad-character list manually if the target is unusual or stateful.
