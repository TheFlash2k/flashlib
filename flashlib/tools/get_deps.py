#!/usr/bin/env python3

"""
Previously a standalone Bash Script 
https://gist.github.com/TheFlash2k/03c103245d3fb44e6c6894f4916deb20

Now part of Flashlib as a whole.
"""

from flashlib.utils import *
import os
import sys
import argparse
import shutil
import sys
from pathlib import Path
from .utils import *
from pwn import info as pwn_info

"""
Set this up so that it's usable as a standalone binary
"""

PATCHERS = ("patchelf", "pwninit")
LIBS_BLACKLIST = ("linux-vdso.so.1")

DEFAULT_OUTFILE_SUFFIX = "patched"
DEFAULT_DOCKERFILE     = "Dockerfile"
DEFAULT_PATCHER        = "patchelf"
DEFAULT_LIBPATH        = "."
DEFAULT_SYMBOLS_FILE   = ".debug"
IMAGE_NAME             = "deps_extraction"
CONTAINER_NAME         = "deps_extraction"
LOADER                 = "ld-linux-x86-64.so.2"

def which_or_die(tool: str) -> None:
	if shutil.which(tool) is None:
		die(f"{tool} not found in PATH. Please install it.")

def realpath(p: str) -> str:
	return str(Path(p).resolve())

def get_binary() -> str:
	cwd = Path(".").resolve()
	endswith = ( ".sh", ".so.6", ".so.2", ".py", ".i64", ".nam", ".yml", ".json", "patched" )
	startswith = ( "ld-", "libstd++", "libgcc", "docker" )
	for p in cwd.iterdir():
		if not p.is_file():
			continue
		name = p.name
		if not os.access(p, os.X_OK):
			continue
		ended = False
		lower = name.lower()
		for end in endswith:
			if lower.endswith(end.lower()):
				ended = True
				break
		if ended: continue
		for start in startswith:
			if lower.startswith(start.lower()):
				ended = True
				break
		if ended: continue
		try:
			return str(p)
		except Exception as E:
			continue

def set_binary(binary: str | None) -> str:
	if not binary:
		binary = get_binary()
	if not binary:
		die("No binary name specified")
	if not Path(binary).is_file():
		die(f"{YELLOW}{binary}{RESET} is not a valid file")

	try:
		e = ELF(binary, checksec=False)
		if e.statically_linked:
			pwn_info(f"Binary {GREEN}{binary}{RESET} is {CYAN}statically linked{RESET}. No need to extract libaries.")
			os._exit(0)
	except:
		die(f"Unable to parse binary {YELLOW}{binary}{RESET} as a valid binary")
	return realpath(binary)

def set_dockerfile(dockerfile: str | None) -> str:
	if not dockerfile:
		dockerfile = DEFAULT_DOCKERFILE

	p = Path(dockerfile)
	if not p.is_file():
		# try to find something like *dockerfile* in current dir
		candidates = list(Path(".").glob("*dockerfile*")) + list(Path(".").glob("*Dockerfile*"))
		candidates = [c for c in candidates if c.is_file()]
		if candidates:
			found = candidates[0].name
			info(f"{RED}{dockerfile}{RESET} was not found! But found {GREEN}{found}{RESET} in the current folder, using that!")
			dockerfile = found

	p = Path(dockerfile)
	if not p.is_file():
		die("Dockerfile not found!")
	return realpath(str(p))

def set_patcher(patcher: str | None) -> str:
	patcher = patcher or DEFAULT_PATCHER
	if patcher not in PATCHERS:
		die(f"Invalid patcher. Only allowed: {RED}{' '.join(PATCHERS)}{RESET}")
	which_or_die(patcher)
	return patcher

def set_libpath(libpath: str | None, force: bool) -> str:
	libpath = libpath or DEFAULT_LIBPATH
	p = Path(libpath)
	if p.exists() and p.is_dir() and str(p) != DEFAULT_LIBPATH and not force:
		die(f"Library Path {libpath} already exists! Use --force|-f")
	p.mkdir(parents=True, exist_ok=True)
	return str(p)

def set_outfile(binary: str, outfile: str | None) -> str:
	default = f"{binary}_{DEFAULT_OUTFILE_SUFFIX}"
	if not outfile:
		# if user never passed -o, we just default silently like bash effectively does
		return default

	if outfile and Path(outfile).exists():
		warn(f"{RED}{outfile}{RESET} is already a file. Defaulting to: {BLUE}{default}{RESET}")
		return default

	return outfile or default

def get_deps_from_bin(binary: str) -> list[str]:
	try:
		res = exec_cmd(["ldd", binary], capture=True, check=True)
	except subprocess.CalledProcessError as e:
		die(f"ldd failed: {e.stderr.strip() if e.stderr else e}")

	deps: list[str] = []
	for line in res.stdout.splitlines():
		line = line.strip()
		if not line:
			continue
		
		"""
		ld usually has an output before => (if patched)
		otherwise ld doesn't have anything else, so
		as a sanity check and future proofing, we simply
		"""
		elems = line.split()
		if len(elems) < 2: continue
		if elems[0] in LIBS_BLACKLIST:
			continue

		"""
		Patched scenarios usually have:
		./ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007722c2ca9000)
		"""
		libpath: str = ""
		if "=>" in elems:
			if 'ld-linux' in elems[0]:
				libpath = elems[0]
			else:
				if len(elems) >= 3:
					libpath = elems[2]
				else:
					info(f"Found library {elems[0]} but unable to find path (Not extracting this.)")
					continue
		else:
			"""
			Usually only for ld scenarios:

			/lib64/ld-linux-x86-64.so.2 (0x000073ac6c5b3000)
			"""
			libpath = elems[0]
		deps.append(libpath)
	return deps

def setup_container(dockerfile: str, debug_symbols: bool, lines: List[str] = []) -> tuple[str, str, str, tempfile.TemporaryDirectory]:
	SUFFIX = 'ENTRYPOINT [ "sleep", "100000" ]'
	which_or_die("docker")

	# Stop existing container with same name (if running)
	res = exec_cmd(["docker", "ps", "--format", "{{.Names}}"], capture=True, check=True)
	if CONTAINER_NAME in res.stdout.splitlines():
		warn(f"Found a container running with name {CYAN}{CONTAINER_NAME}{RESET}. Stopping it before continuing")
		exec_cmd(["docker", "stop", CONTAINER_NAME], check=False)

	img_name = extract_image_from_dockerfile(dockerfile)
	log(f'Extracted Image from "{RED}{dockerfile}{RESET}": {YELLOW}{img_name}{RESET}')

	tmpdir = tempfile.TemporaryDirectory()
	tmp_path = Path(tmpdir.name) / "temp_Dockerfile"
	dockerfile_lines = [
		f"FROM {img_name}"
	]
	if lines:
		dockerfile_lines += lines

	# If it looks like a Debian/Ubuntu-ish image and debug_symbols requested, install libc6-dbg
	base = img_name.split("@", 1)[0].split(":", 1)[0].lower()
	debianish = any(x in base for x in ["theflash", "ubuntu", "debian", "slim-buster", "jess"])

	if debianish and debug_symbols:
		log("Adding debugging symbols for libc")
		lines = (
			"ENV TZ=Asia/Karachi",
			"ENV DEBIAN_FRONTEND=noninteractive",
			"RUN apt update -y && apt install -y libc6-dbg"
		)
		dockerfile_lines += lines
	dockerfile_lines.append(SUFFIX)

	tmp_path.write_text("\n".join(dockerfile_lines), encoding="utf-8")
	log(f"Wrote temporary Dockerfile: {YELLOW}{tmp_path}{RESET}")
	log(f"Building image {CYAN}{IMAGE_NAME}{RESET}.")
	exec_cmd(["docker", "build", "-f", str(tmp_path), "-t", IMAGE_NAME, "."], check=True)
	log(f"Built image with name: {YELLOW}{IMAGE_NAME}{RESET}")

	res = exec_cmd(["docker", "run", "-d", "--rm", "-q", "--name", CONTAINER_NAME, IMAGE_NAME], capture=True, check=True)
	container_id = res.stdout.strip()
	info(f"Ran container ({CYAN}{CONTAINER_NAME}{RESET}) with id {YELLOW}{container_id}{RESET}")

	return container_id, IMAGE_NAME, str(tmp_path), tmpdir

def run_docker_cmd(container_name: str, cmd: str) -> str:
	res = exec_cmd(["docker", "exec", container_name, "sh", "-c", cmd], capture=True, check=False)
	out = (res.stdout or "").strip()
	return out

def get_realpath(container_name: str, file: str) -> str:
	return run_docker_cmd(container_name, f"realpath '{file}' 2>/dev/null")

def find_and_copy(container_id: str, lib: str, libpath: str) -> None:
	if not lib:
		return

	lib = get_realpath(CONTAINER_NAME, lib)
	if not lib:
		warn(f"Unable to find {dep_name} inside the container.")
		return

	libname = Path(lib).name
	outfile_path = str(Path(libpath) / libname)

	res = exec_cmd(["docker", "cp", f"{container_id}:{lib}", outfile_path], check=False)
	if res.returncode != 0:
		warn(f"Unable to copy file {lib} from the container :(")
		return

	info(f'Copied from {YELLOW}"{lib}"{RESET} to {CYAN}"{outfile_path}"{RESET}')
	try:
		os.chmod(outfile_path, os.stat(outfile_path).st_mode | 0o111)
	except Exception:
		pass

def patch_binary(binary: str, outfile: str, patcher: str, libpath: str, debug_symbols_file: str, no_debug_symbols: bool, libs: list) -> None:
	log(f"Patching {YELLOW}{binary}{RESET} using {CYAN}{patcher}{RESET} to {RED}{outfile}{RESET}")

	if patcher == "patchelf":
		try:
			shutil.copy2(binary, outfile)
		except Exception:
			die("Unable to make clone of the file. Please check directory permissions")

		loader = ""
		for lib in libs:
			if 'ld' in lib:
				loader = str(Path(lib).name)
		if loader == "":
			loader = str(Path(libpath) / LOADER)

		"""
		As I personally saw and reported by @72ghoul & @Arcusten, the binary had it's symbols
		stripped everytime patchelf modified the ELF headers, for some reason, the function
		debugging symbols would break and the binary would stop working. To fix that,
		I found an objcopy trick which we can use to copy the debugging symbols from the original
		binary, create a new symbols-only file and then using objcopy, setup the debuglink
		to get the debugging symbol in the patched binary. The only downside we have is that
		we will have a new file (--debug-symbols-file | -df) in the directory, other than
		that, nothing so it works.

		objcopy --only-keep-debug binary binary.debug
		objcopy --add-gnu-debuglink=binary.debug binary
		"""
		if not no_debug_symbols:
			log("Copying debugging symbols from original binary")
			exec_cmd(["objcopy", "--only-keep-debug", binary, debug_symbols_file])
		else:
			log(f"Not adding debugging symbols ({RED}--no-debug-symbols{RESET} specified)")
		exec_cmd(["patchelf", "--set-interpreter", loader, "--set-rpath", libpath, outfile], check=True)
		if not no_debug_symbols:
			exec_cmd(["objcopy", f"--add-gnu-debuglink={debug_symbols_file}", outfile])

	elif patcher == "pwninit":
		exec_cmd(["pwninit", "--no-template", "--bin", binary], check=True)
	else:
		die(f"Invalid binary to patch using: {RED}{patcher}{RESET}")
	info("Done patching!")

def cleanup(container_id: str) -> None:
	log("Cleaning up....")
	exec_cmd(["docker", "stop", CONTAINER_NAME], check=False)
	pwn_info(f"Stopped ({RED}{CONTAINER_NAME}{RESET}) {YELLOW}{container_id}{RESET}")

	res = exec_cmd(["docker", "rmi", IMAGE_NAME], check=False)
	if res.returncode != 0:
		die(f"Unable to delete {RED}{IMAGE_NAME}{RESET}")
	info(f"Deleted {RED}{IMAGE_NAME}{RESET}")

def main(argv: list = None) -> int:
	parser = argparse.ArgumentParser(
		prog="get-deps",
		add_help=True,
		formatter_class=argparse.RawTextHelpFormatter,
	)
	parser.add_argument("-b", "--binary", help="Binary to patch [Defaults to first executable found by directory iteration]", required=False)
	parser.add_argument("-d", "--dockerfile", default=DEFAULT_DOCKERFILE, help=f"Dockerfile to extract libraries from [Default: {DEFAULT_DOCKERFILE}]")
	parser.add_argument("-o", "--outfile", help="Output file name [Default: [BINARY]_patched]", required=False)
	parser.add_argument("-p", "--patcher", default=DEFAULT_PATCHER, help=f"The binary to use for patching [Default: {DEFAULT_PATCHER}]")
	parser.add_argument("-D", "--debug", action="store_true", help="Add debugging symbols for libc (only APT pkg mgr works [Debian/Ubuntu])")
	parser.add_argument("-L", "--lib-only", action="store_true", help="Only fetch the libraries and don't do patching")
	parser.add_argument("-l", "--lib-path", default=DEFAULT_LIBPATH, help=f"The output path where the libraries will be stored [Default: {DEFAULT_LIBPATH}]")
	parser.add_argument("-dl", "--dockerfile-lines", default="", help="Additional lines that you want to add to the underlying Dockerfile. Must be \\n seperated. Example: --lines \"RUN id\\nWORKDIR /app\"", dest='lines')
	parser.add_argument("-df", "--debug-symbols-files", default=DEFAULT_SYMBOLS_FILE, help=f"The name of the file in which the debugging symbols will be stored by objcopy. [Default: {DEFAULT_SYMBOLS_FILE}]", dest='debug_symbols_file')
	parser.add_argument("-nd", "--no-debug-symbols", action='store_true', help="Do not copy debugging symbols from the original file", dest='no_debug_symbols')
	parser.add_argument("-f", "--force", action="store_true", help="Force overwriting the files and folder")

	args = parser.parse_args(argv)
	binary = set_binary(args.binary)
	dockerfile = set_dockerfile(args.dockerfile)
	patcher = set_patcher(args.patcher)
	libpath = set_libpath(args.lib_path, args.force)
	outfile = set_outfile(binary, args.outfile)

	pwn_info(f"Using binary    : {GREEN}{binary}{RESET}")
	pwn_info(f"Using Dockerfile: {GREEN}{dockerfile}{RESET}")
	pwn_info(f"Using Patcher   : {GREEN}{patcher}{RESET}")
	pwn_info(f"Using Lib Path  : {GREEN}{libpath}{RESET}")
	pwn_info(f"Using Output    : {GREEN}{outfile}{RESET}")

	deps = get_deps_from_bin(binary)
	pwn_info("Found dependant libaries:")
	for dep in deps:
		print(f"\t - {YELLOW}{dep}{RESET}")

	lines = args.lines.split('\\n') if args.lines else ""

	if lines:
		pwn_info(f"Using Lines:")
		for line in lines:
			print(f"\t - {CYAN}{line}{RESET}")

	container_id = ""
	tmpdir = None

	try:
		pass
		container_id, _, _, tmpdir = setup_container(dockerfile, args.debug, lines)

		for dep in deps:
			find_and_copy(container_id, dep, libpath)

		if not args.lib_only:
			patch_binary(binary, outfile, patcher, libpath, args.debug_symbols_file, args.no_debug_symbols, deps)
	except Exception as e:
		print(f"Error: {e}")
		os._exit(0)

	finally:
		if container_id:
			cleanup(container_id)
		if tmpdir is not None:
			tmpdir.cleanup()

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
