import os
import sys

# I am pretty sure that half of these functions are absolutely useless.
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RESET = "\033[0m"

def log(msg: str) -> None:
	print(f"{GREEN}[*]{RESET} {msg}")

def warn(msg: str) -> None:
	print(f"{YELLOW}[?]{RESET} {msg}")

def info(msg: str) -> None:
	print(f"{BLUE}[+]{RESET} {msg}")

def die(msg: str, code: int = 1) -> "NoReturn":
	print(f"{RED}[!]{RESET} {msg}", file=sys.stderr)
	raise SystemExit(code)

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
