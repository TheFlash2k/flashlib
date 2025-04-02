all: compile build run
compile:
	gcc -o ret2plt -fno-stack-protector -no-pie ret2plt.c
	cp ret2plt ret2plt_patched
	patchelf --set-interpreter ./ld-2.31.so --set-rpath . ./ret2plt_patched
build:
	docker build -t flashlib_example_ret2plt .
run:
	docker run -it --rm -p 31337:8000 flashlib_example_ret2plt
clean:
	rm -f ret2plt ret2plt_patched
	docker rmi -f flashlib_example_ret2plt
