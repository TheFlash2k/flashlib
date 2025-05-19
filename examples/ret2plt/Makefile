CHALLENGE := ret2plt
FLAGS := -fno-stack-protector -no-pie
all: compile build run
compile:
	gcc -o $(CHALLENGE) $(FLAGS) $(CHALLENGE).c
	cp $(CHALLENGE) $(CHALLENGE)_patched
	patchelf --set-interpreter ./ld-2.31.so --set-rpath . ./$(CHALLENGE)_patched
build:
	docker build -t flashlib_example_$(CHALLENGE) .
run:
	docker run -d \
		--rm \
		-p 31337:8000 \
		--cap-add NET_ADMIN \
		--name flashlib_example_$(CHALLENGE) \
		flashlib_example_$(CHALLENGE)
stop:
	docker stop flashlib_example_$(CHALLENGE)
clean:
	rm -f $(CHALLENGE) $(CHALLENGE)_patched
	docker rmi -f flashlib_example_$(CHALLENGE)
