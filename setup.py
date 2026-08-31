from setuptools import setup, find_packages

setup(
    name="supaguard-cli",
    version="1.0.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "supaguard=supaguard.cli:main",
        ],
    },
)
