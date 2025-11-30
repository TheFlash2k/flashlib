"""
tcache.py

This will contain all implementations related to Tcache and some random stuff.
"""

from typing import List, Dict, Union, Optional
from pwn import error, warn, p16, u64, p64
from .utils import chunkify, encode

TCACHE_MAX_BINS = 0x40
TCACHE_START    = 0x20
TCACHE_END      = 0x410
ERRNO           = 0xDEADDEADBEEFBEEF

class tcache_perthread_struct:
	_counts:  Dict[int, int] = {}
	_entries: Dict[int, int] = {}
	TCACHE_RANGE = range(TCACHE_START, TCACHE_END+1, 0x10)

	def _validate_bin(self, bin: int) -> int:
		"""
		Validate if the requested bin is in the tcache range and
		is a multiple of 0x10 to keep everything organized.
		"""
		return (TCACHE_START <= bin <= TCACHE_END) and ((bin % 0x10) == 0)

	def _to_bytes(self) -> bytes:
		"""
		Converts the entire tcache struct properly to bytes
		"""
		_struct = b""
		for count in self._counts.values():
			_struct += p16(count)
		for entry in self._entries.values():
			_struct += p64(entry)
		return _struct

	def __init__(self):
		for i in self.TCACHE_RANGE:
			self._counts[i] = self._entries[i] = 0

	def __getitem__(self, entry: int) -> int:
		"""
		Returns the entry from entries.

		Entry MUST be in the range 0x20 - 0x420 and must be a multiple of 0x10
		"""
		if not self._validate_bin(entry):
			return ERRNO
		return self._entries[entry]

	def __setitem__(self, entry: int, value: int) -> int:
		"""
		Set an entry in the entries and increment the count for it too.
		"""
		if not self._validate_bin(entry):
			return ERRNO

		if self._counts[entry] >= 7:
			info("[WARN] Cannot add more than 7 entries in %#x count" % entry)
			return ERRNO

		self._counts[entry] += 1
		self._entries[entry] = value & 0xFFFFFFFFFFFFFFFF

	def __bytes__(self) -> bytes:
		"""
		When a tc object is passed to a `bytes` function, this function will
		be invoked
		"""
		return self._to_bytes()

	def __add__(self, other: bytes) -> bytes:
		if isinstance(other, bytes):
			return self._to_bytes() + other
		return self._to_bytes() + encode(other)

	def set_count(self, bin: int, count: int):
		"""
		Sets the count for a particular tcache bin

		bin: int
			The tcache bin of which we want to set the count of
				0x20 <= bin <= 0x410

		count: int
			The actual count we want to set.
				0 <= count <= 7
		"""
		if not (0 <= count <= 7):
			count = 7

		if not self._validate_bin(bin):
			return ERRNO

		self._counts[bin] = count

	def set_entry(self, bin: int, entry: int):
		"""
		Sets the entry for a particular tcache bin

		bin: int
			The tcache bin of which we want to set the count of
				0x20 <= bin <= 0x410

		entry: int
			The pointer we want to set
		"""
		if not self._validate_bin(bin):
			return ERRNO

		self._entries[bin] = entry & 0xFFFFFFFFFFFFFFFF

	def set(self, bin: int, entry: int, count: int = 1):
		"""
		Sets the entry [and count] for a particular tcache bin

		bin: int
			The tcache bin of which we want to set the count of
				0x20 <= bin <= 0x410

		entry: int
			The pointer we want to set

		count: int
			The actual count we want to set.
				0 <= count <= 7
		"""
		self.set_count(bin, count)
		self.set_entry(bin, entry)

	def set_between(self, start: int, end: int, values: Union[List[int], bytes]):
		"""
		Set entries between start and end (inclusive)

		start: int
			The starting bin where we will start writing our values

		end: int
			The ending bin (inclusive) where we'll write our final value

		values: Union[List[int], bytes]
			List of int or a set of bytes that we'll write from start to
			end
		"""
		if start < 0x20: start = 0x20
		if end > 0x410:  end = 0x410
		if end <= start: error("end cannot be smaller than or equal to start")

		if (start % 0x10) != 0:
			start += start % 0x10

		if (end % 0x10) != 0:
			end += end % 0x10
			if end > 0x410: end = 0x410

		count = ((end - start) // 0x10) + 1
		if not isinstance(values, list) and not isinstance(values, bytes):
			error("Values can either be a list of int or bytes")

		if len(values) == 0:
			error("Values cannot be empty!")

		if isinstance(values, list):
			original_len = len(values)
			for i in range(original_len, count):
				values.append(values[i % original_len])

			for i in range(len(values)):
				if not isinstance(values[i], int):
					"""
					Allowed is a list of ints, nothing else.
					"""
					error("Values list can only contain int values.")
				values[i] &= 0xFFFFFFFFFFFFFFFF

		elif isinstance(values, bytes):
			c = (count+1) * 0x10

			if len(values) < c:
				times = (c + len(values) - 1) // len(values)
				values = (values * times)[:c]
			values = [u64(i) for i in chunkify(values, 8)]

		it = 0
		for i in range(start, end+1, 0x10):
			self._counts[i] = (self._counts[i] + 1) % 7
			self._entries[i] = values[it]
			it += 1

	def get_until(self, bin: int, include_counts: bool = True) -> bytes:
		""" Returns the data in bytes till `bin` bins """
		if not self._validate_bin(bin):
			error("Invalid tcache bin")

		_struct = b""
		if include_counts:
			for count in self._counts.values():
				_struct += p16(count)

		idx = (bin // 0x10) - 0x2
		vals = list(self._entries.values())
		for i in range(0, idx+1):
			_struct += p64(vals[i])
		return _struct

	def vis(self):
		"""
		Visualize the struct in the similar format as the "vis" command
		in GDB

		0x0000000000000000: 0x0000000000000000 0x0000000000000000
		0x0000000000000010: 0x0000000000000000 0x0000000000000000
		"""
		print("="*0x1a + " VIS " + "="*0x1a)
		addr = 0x0
		print(f"0x{addr:016x}: 0x{0:016x} 0x{0x291:016x}")
		addr += 0x10

		elems = list(self.TCACHE_RANGE)
		for _ in range(0, len(elems), 8):
			"""
			Range only for count
			"""
			opt = elems[_:_+8]
			encoded = [p16(self._counts[i] & 0xFFFF) for i in opt]
			v1, v2 = [u64(i) for i in chunkify(b"".join(encoded), 8)]
			print(
				f"0x{addr:016x}: "
				f"0x{v1:016x} 0x{v2:016x}"
			)
			addr += 0x10

		for _ in range(0, len(elems), 2):
			"""
			Range for entries
			"""
			opt = elems[_:_+2]
			entries = self._entries[opt[0]], self._entries[opt[1]]
			print(
				f"0x{addr:016x}: "
				f"0x{entries[0]:016x} 0x{entries[1]:016x}"
			)
			addr += 0x10
		print("="*57)