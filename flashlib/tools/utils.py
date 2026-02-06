import os
import sys
from pathlib import Path

# I am pretty sure that half of these functions are absolutely useless.
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RESET = "\033[0m"

def realpath(p: str) -> str:
	return str(Path(p).resolve())

def log(msg: str) -> None:
	print(f"{GREEN}[*]{RESET} {msg}")

def warn(msg: str) -> None:
	print(f"{YELLOW}[?]{RESET} {msg}")

def info(msg: str) -> None:
	print(f"{BLUE}[+]{RESET} {msg}")

def die(msg: str, code: int = 1) -> "NoReturn":
	print(f"{RED}[!]{RESET} {msg}", file=sys.stderr)
	raise SystemExit(code)

def which_or_die(tool: str) -> None:
	if shutil.which(tool) is None:
		die(f"{tool} not found in PATH. Please install it.")

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

def find_dockerfile(dockerfile: str = None) -> str:
	"""
	Finds a dockerfile in the current folder if no dockerfile is provided
	"""
	if not dockerfile:
		dockerfile = "Dockerfile"

	p = Path(dockerfile)
	if not p.is_file():
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

def extract_image_from_dockerfile(dockerfile: str) -> str:
	"""
	When porting from bash to python, I rewrote this function
	with a bit more fixes that I knew were problematic in bash
	but due to my limited knowledge, I couldn't get around those.
	"""
	if not os.path.exists(dockerfile):
		die(f"Dockerfile {RED}{dockerfile}{RESET} not found!")

	with open(dockerfile, "r", encoding="utf-8", errors="ignore") as f:
		lines = [i.strip() for i in f.readlines() if len(i) > 1]
		for i in range(len(lines)):
			line = lines[i].strip()
			if not line or line.startswith("#"):
				continue
			if line.upper().startswith("FROM "):
				# "FROM image:tag AS name"
				rest = line.split(None, 1)[1]
				img = rest.split()[0]

				"""
				In certain cases, authors use:
				FROM pwn.red/jail
				COPY --from=ubuntu:22.04 / /srv
				"""
				if img.lower() == "pwn.red/jail":
					try:
						# we iterate over the remaining lines:
						if i >= (len(lines) - 1): # end of file
							break
						remaining = "\n".join(lines[i:])
						# the only other part as a whole that can contain the image name
						# is --from=.* <something>, so we just simply split
						img = remaining.split("--from=")
						if len(img) == 1: break
						img = img[1].split()[0]
					except Exception as E:
						# there might be some logic error in parsing so better be careful.
						die(f"An error occured when parsing: {E}")
				return img
	die(f"Could not find a {RED}FROM/--from{RESET} in {dockerfile}")
