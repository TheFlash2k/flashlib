# flashlib

A wrapper around pwntools but also with a few of the functions that I use on a daily basis.

---

To install, run:

```bash
pip3 install pwn-flashlib
```

## Basic usage:

```py
from flashlib import *

# This will setup everything for you, elf, libc
init("./test")

# => io is in the global namespace
# <do your exploitation part here>

io.interactive()
```

## Calculating offsets by `recvafter`

```py
#!/usr/bin/env python3

from flashlib import *

# Just init and io, libc and elf will be in the global space
init("./test")

main = hexleak(io.recvafter(b": "))
elf.address = main - elf.sym.main
logleak(elf.address)

io.interactive()
```

## Attaching GDB:

When running the exploit, run it as: `python3 exploit.py GDB` and use the attach method to attach a gdb to the current process.

> The context.terminal is set to `tmux`, you can override to your liking.

```py
#!/usr/bin/env python3

from flashlib import *

gdbscript = """
	b *main+40
"""

init("./test")
attach(gdbscript) # this will attach the gdb session

io.interactive()
```

### REMOTE:

Let's consider a scenario where you have setup a remote gdb session, you need to just pass `REMOTE` and `GDB` and in attach, just pass `remote=("127.0.0.1", GDBPORT)` and you'll be prompted to attach gdb? i.e. attach the gdbserver to the process.

```py
#!/usr/bin/env python3

from flashlib import *

gdbscript = """
	b *main+40
"""

init("./test")
attach(gdbscript, remote=("127.0.0.1", 1234))
```

### CUSTOM IO:

Another scenario where you have both a local and a remote connection, you can pass custom pwnlib.tubes process to attach the gdb session to.

```py
#!/usr/bin/env python3

from flashlib import *

gdbscript = """
	b *main+40
"""

local, elf, libc = init("./test")
io = remote("127.0.0.1", 31337)

# This will now 
attach(gdbscript, _io=local)
```

## Proof-of-Work

Since my pwn-chal container now supports proof-of-work which is quite similar to `pwn.red/jail`, I just had a function lying around to solve the proof-of-work:

```py
#!/usr/bin/env python3

init("./test")

# just invoke the function and it will solve pow
# no need to pass anything else.
# Handles pow for:
# 1. pwn-chal
# 2. pwn.red/jail
pow_solve()
```

---

There's a lot more stuff which I'll keep updating as well.

---