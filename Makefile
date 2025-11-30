install:
	sudo python3 setup.py install

push:
	python3 setup.py sdist bdist_wheel
	twine upload dist/*.whl

clean:
	sudo rm -rf build dist pwn_flashlib.egg-info
