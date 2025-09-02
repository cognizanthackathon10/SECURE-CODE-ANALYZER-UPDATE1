from setuptools import setup, find_packages

setup(
    name="secure-code-analyzer",
    version="0.1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        # put dependencies here, e.g.
        # "requests",
    ],
    entry_points={
        "console_scripts": [
            "sca=secure_code_analyzer.cli:main",  # this creates the `sca` command
        ],
    },
    python_requires=">=3.7",
)
