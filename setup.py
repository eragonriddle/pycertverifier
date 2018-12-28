import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
        name="pycertverifier",
        version="0.0.1",
        author="Eragon Riddle",
        author_email="eragonriddle@gmail.com",
        description="A python package to check x509 certificate validity",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/eragonriddle/pycertverifier",
        packages=setuptools.find_packages(),
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
)
