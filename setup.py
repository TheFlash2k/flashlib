from setuptools import setup, find_packages

setup(
    name="pwn-flashlib",
    version="0.1.3",
    packages=find_packages(),
    install_requires=['pwntools'],
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
    python_requires='>=3.6',
)
