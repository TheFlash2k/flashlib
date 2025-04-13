"""
All my utility (small) functions/lambdas
"""

from pwn import *
from functools import wraps
from typing import Any, List
from tqdm import *
from enum import Enum

context.terminal = ["tmux", "splitw", "-h"]
context.arch = 'amd64'
context.log_level = 'info'

"""
Copy pasta from:
https://mgarod.medium.com/dynamically-add-a-method-to-a-class-in-python-c49204b85bd6
"""
def add_method(cls):
	def decorator(func):
		@wraps(func) 
		def wrapper(self, *args, **kwargs): 
			return func(self, *args, **kwargs)
		setattr(cls, func.__name__, wrapper)
		# Note we are not binding func, but wrapper which accepts self but does exactly the same as func
		return func # returning func means func can still be used normally
	return decorator

"""
Most of the functions below were once lambdas.

Now they're smol functions with docstrings
"""

def ptr_mangle(addr: int, secret: int, rot: int = 0x11) -> int:
	"""
	addr: int
		The address you want to mangle.

	secret: int
		The secret that will be xor'ed with the address
		This is found inside TLS [FS:0x30].

	rot: int
        The rotation amount.
        Default: 0x11
	"""
	return rol(addr ^ secret, rot)

def ptr_demangle(addr: int, secret: int, rot: int = 0x11) -> int:
	"""
	addr: int
		The address you want to demangle.

	secret: int
		The secret that will be xor'ed with the address
		This is found inside TLS [FS:0x30].

	rot: int
        The rotation amount.
        Default: 0x11
	"""
	return ror(addr, rot) ^ secret

def mangle(heap_addr: int, val: int) -> int:
	"""
    heap_addr: int
        The address of the chunk that will be mangled
		
	val: int
        The value that will be mangled.
	"""
	return (heap_addr >> 12) ^ val

def demangle(val: int):
	"""
	val: int
        The value that will be used for safelinking demangling
	"""
	mask = 0xfff << 52
	while mask:
		v = val & mask
		val ^= (v >> 12)
		mask >>= 12
	return val

def encode(buf: Any) -> bytes:
	"""
	buf: Any
        The buffer that you want to encode.
		If it's in bytes, it is returned as is,
		if not, it is converted to a string and then
		encoded.
	"""
	return buf if isinstance(buf, bytes) else str(buf).encode()

def hexleak(leak: bytes) -> int:
	"""
	leak: bytes
        Converts a leak in bytes into an integer.
		
		Examples:
            hexleak(b"0x4141414141") would return 280267669825
		
		> It automatically removes newline if there are any.
	"""
	if encode(leak[-1]) == b"\n":
		leak = leak[:-1]
	return int(leak, 0x10)

def fixleak(leak: bytes, padding: bytes = b"\x00") -> int:
	"""
    leak: bytes
        Converts raw leaked bytes into an integer.
	
	padding:
        The character that will be used as padding.
		Default: 0x0 (NULL)
		
    Example:
        fixleak(b"\x00\x41\x24\x26\x42") would return 1109795905
			
	"""
	if encode(leak[-1]) == b"\n":
		leak = leak[:-1]
	return unpack(leak.ljust(8, padding))
	
def rfixleak(leak: bytes, padding: bytes = b"\x00") -> int:
	"""
    leak: bytes
        Converts raw leaked bytes into an integer.
	
	padding:
        The character that will be used as padding.
		Default: 0x0 (NULL)
		
    The difference between this and fixleak is
	that fixleak appends to left, and this appends
	to the right.
	"""
	if encode(leak[-1]) == b"\n":
		leak = leak[:-1]
	return unpack(leak.rjust(8, padding))

def diff_hn(new: int, last: int) -> int:
	"""
    new: int
        The new value that needs to be written at the address.
		
	last: int
        The last value that already exists at the address.
	"""
	return (new - last) % 65536

def diff_hhn(new: int, last: int) -> int:
	"""
    new: int
        The new value that needs to be written at the address.
		
	last: int
        The last value that already exists at the address.
	"""
	return (new - last) % 256

def func_byte_array_hhn(func_addr: int) -> List[int]:
	"""
	func_addr: int
        Takes in an address and divides it into a list
		which contains 1-byte at each index.
		
	Example:
        func_addr(0x41424344)
            would return: [0x44, 0x43, 0x42, 0x41]
	"""
	return [(func_addr >> (8 * i)) & 0xFF for i in range((func_addr.bit_length() + 7) // 8)]

def func_byte_array_hn(func_addr: int) -> List[int]:
	"""
	func_addr: int
        Takes in an address and divides it into a list
		which contains 2-bytes at each index.
		
	Example:
        func_addr(0x4142434445464748)
            would return: [0x4748, 0x4546, 0x4344, 0x4142]
	"""
	return [(func_addr >> (16 * i)) & 0xFFFF for i in range((func_addr.bit_length() + 7) // 16)]

def p24(addr: int) -> bytes:
	"""
	Converts an address to 24-bits
		
	addr: int
        The address you want to convert
	"""
	return p32(addr)[:-1]

def p56(addr: int) -> bytes:
	"""
	Converts an address to 56-bits
		
	addr: int
        The address you want to convert
	"""
	return p64(addr)[:-1]

def big_p24(addr: int) -> bytes:
	"""
	Converts an address to 24-bits in Big Endian

	addr: int
        The address you want to convert
	"""
	return p32(addr, endianness='big')[:-1]

def big_p32(addr: int) -> bytes:
	"""
	Converts an address to 32-bits in Big Endian
		
	addr: int
        The address you want to convert
	"""
	return p32(addr, endianness='big')

def big_p56(addr: int) -> bytes:
	"""
	Converts an address to 56-bits in Big Endian
	
	addr: int
        The address you want to convert
	"""
	return p64(addr, endianness='big')[:-1]

def big_p64(addr: int) -> bytes:
	"""
	Converts an address to 64-bits in Big Endian
		
	addr: int
        The address you want to convert
	"""
	return p64(addr, endianness='big')

def one_gadget(libc: ELF) -> List[int]:
	"""
	Extracts one gadgets from an existing libc object.
	
	libc: ELF
        The ELF object of libc
	"""
	base_addr = libc.address
	info("Extracting one-gadgets for %s with base @ %#x" % (libc.path, base_addr))
	return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', libc.path]).decode().split(' ')]

def my_fill(data: bytes, mod: int = 0x8, pad_char: bytes = b"|") -> bytes:
	"""
	Does padding to fill the data to be a modulus of `mod`
	
	data:
        The data that you want pad
		
	mod:
        The modulus of which the lenght of `data` will be.
		Default: 0x8
		
	pad_char:
        The character that will be used as padding.
        Default: |
	"""
	return encode(data) + encode(pad_char) * (len(encode(data)) % mod)

def logleak(var: int):
	import inspect
	"""
    var: int
        Fetches the variable name and prints it as:
		<name> @ %#x <value>
	"""
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

def prange(start = 0x0, stop = 0x0, step = 0x1):
	"""
	prange simply makes use of tqdm and prints the range
	"""
	if start != 0x0 and stop == 0x0:
		return tqdm(range(start))
	return tqdm(start, stop, step)

class Limits(Enum):
	"""
	The limits of the different data types in C.
	"""
	INT_MIN   = -0x80000000
	INT_MAX   = 0x7FFFFFFF
	UINT_MIN  = 0x00000000
	UINT_MAX  = 0xFFFFFFFF
	LONG_MIN  = -0x8000000000000000
	LONG_MAX  = 0x7FFFFFFFFFFFFFFF
	ULONG_MIN = 0x0000000000000000
	ULONG_MAX = 0xFFFFFFFFFFFFFFFF
	FLT_MIN   = -3.402823466E+38
	FLT_MAX   = 3.402823466E+38
	DBL_MIN   = -1.7976931348623158E+308
	DBL_MAX   = 1.7976931348623158E+308