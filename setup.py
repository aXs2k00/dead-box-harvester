"""Setup configuration"""

from setuptools import setup, find_packages

setup(
    name="dead-box-harvester",
    version="1.0.0",
    description="Windows dead-box credential and PII extractor",
    author="Forensic Team",
    packages=find_packages(),
    install_requires=[
        "regipy>=0.9.0",
        "python-registry>=1.12.0",
        "impacket>=0.12.0",
        "cryptography>=41.0.0",
        "pycryptodome>=3.18.0",
        "pandas>=2.0.0",
        "construct>=2.10.0",
    ],
    entry_points={
        "console_scripts": [
            "dead-box-harvester=dead_box_harvester.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
