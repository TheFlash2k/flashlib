from setuptools import setup, find_packages

setup(
    name="pwn-flashlib",
    version="0.4.0",
    packages=find_packages(),
    install_requires=['pwntools', 'tqdm', 'argparse', 'docker'],
    author="TheFlash2k",
    author_email="alitaqi2000@gmail.com",
    description="A wrapper around pwntools but also with a few of the functions that I use on a daily basis.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/theflash2k/flashlib",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "get-deps=flashlib.tools.get_deps:main",
        ],
    },    
    python_requires='>=3.6',
)