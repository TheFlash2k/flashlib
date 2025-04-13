CHALLENGE := basic-rop
FLAGS := -fno-stack-protector -no-pie -w
all: compile build run
compile:
	gcc -o $(CHALLENGE) $(FLAGS) $(CHALLENGE).c
	cp $(CHALLENGE) $(CHALLENGE)_patched
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./$(CHALLENGE)_patched
build:
	docker build -t flashlib_example_ret2plt .
run:
	docker run -it --rm -p 31337:8000 flashlib_example_ret2plt
clean:
	rm -f ret2plt ret2plt_patched
	docker rmi -f flashlib_example_ret2plt
