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

# Standalone Utilities:

## get-deps

This is one of my most used scripts that simply extracts all the dependencies from a Dockerfile and patches the binary for you. It was previously written in bash and had to be manually added in path but now it's part of flashlib.

### Usage:

```
usage: get-deps [-h] [-b BINARY] [-d DOCKERFILE] [-o OUTFILE] [-p PATCHER] [-D] [-L] [-l LIB_PATH] [-dl LINES] [-df DEBUG_SYMBOLS_FILE] [-nd] [-f]

options:
  -h, --help            show this help message and exit
  -b BINARY, --binary BINARY
                        Binary to patch [Defaults to first executable found by directory iteration]
  -d DOCKERFILE, --dockerfile DOCKERFILE
                        Dockerfile to extract libraries from [Default: Dockerfile]
  -o OUTFILE, --outfile OUTFILE
                        Output file name [Default: [BINARY]_patched]
  -p PATCHER, --patcher PATCHER
                        The binary to use for patching [Default: patchelf]
  -D, --debug           Add debugging symbols for libc (only APT pkg mgr works [Debian/Ubuntu])
  -L, --lib-only        Only fetch the libraries and don't do patching
  -l LIB_PATH, --lib-path LIB_PATH
                        The output path where the libraries will be stored [Default: .]
  -dl LINES, --dockerfile-lines LINES
                        Additional lines that you want to add to the underlying Dockerfile. Must be \n seperated. Example: --lines "RUN id\nWORKDIR /app"
  -df DEBUG_SYMBOLS_FILE, --debug-symbols-files DEBUG_SYMBOLS_FILE
                        The name of the file in which the debugging symbols will be stored by objcopy. [Default: .debug]
  -nd, --no-debug-symbols
                        Do not copy debugging symbols from the original file
  -f, --force           Force overwriting the files and folder
```

tl;dr: To use this, just run `get-deps` and if a Dockerfile is present in the folder along with a binary, it will get all the dependencies by running `ldd` on the binary, extracting all dependencies, extracting the image from `FROM/--from` and creating a new container and copying all the libraries from there and patching the binary (preserving the debugging symbols too (problem with `patchelf`).)

---

There's a lot more stuff which I'll keep updating as well.

---