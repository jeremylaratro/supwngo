# Positive-control exploit fixtures

Two supwngo-generated exploit scripts that **genuinely obtain an interactive
shell** on their targets. They are checked in unmodified (exactly as
`supwngo autopwn -o` emitted them) to serve as positive controls for changes
to `benchmark/run_bench.py`.

## Why these two specifically

Nine of the corpus binaries embed their flag in `.rodata` and surrender it by
reaching `win()`. The remaining six — `01_shellcode_stack`,
`02_ret2plt_system`, `03_pie_leak_ret2libc`, `07_ret2libc_leak`,
`08_ret2dlresolve`, `09_srop` — contain no flag at all. For those, the *only*
route to a flag is `cat flag.txt` executed inside a shell the exploit obtained,
which means they depend on the harness both:

1. keeping the target process alive long enough for the shell to be usable, and
2. writing shell commands to the exploit's stdin.

Any change that shortens, reorders, or removes the stdin the harness injects can
silently turn a *working* shell exploit into a `FAILED`. These two scripts are
the cheapest way to detect that: they are known-good, so if they stop producing
the flag, the harness regressed — not supwngo.

`01` is a stack-shellcode shell (`execve("/bin/sh")` from injected code on a
leaked stack address) and `02` is a ret2plt shell (`system("/bin/sh")` through
the binary's own PLT), so between them they cover both ways a shell can be
obtained in this corpus.

## Running one standalone

Each script resolves its target by absolute path, and falls back to a binary of
the same name sitting next to the script, so either of these works:

```sh
# from anywhere, against the in-tree corpus
python3 benchmark/fixtures/positive-controls/02_ret2plt_system_shell.py

# or copy the script next to a built target and run it there
cp benchmark/fixtures/positive-controls/02_ret2plt_system_shell.py /some/dir/
```

Run non-interactively — the same way `run_bench.py:independent_verify()` does —
by piping shell commands in:

```sh
printf 'cat flag.txt\nexit\n' | \
  TERM=xterm PWNLIB_NOTERM=1 \
  python3 benchmark/fixtures/positive-controls/02_ret2plt_system_shell.py
```

The target's flag file must exist; `benchmark/build_all.sh` writes it next to
each binary. A successful run ends with the flag on stdout. Both scripts end in
`io.interactive()`, so they need `TERM` set and exit when stdin closes.

## Ground rules

- **Do not edit these files to make them pass.** They are a measuring
  reference; if one fails, fix the harness or record the fixture as genuinely
  stale and regenerate it with `supwngo autopwn -o`.
- They are *positive* controls only. The negative controls (does a target
  yield its flag with no exploit at all?) belong with the harness.
