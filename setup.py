#!/usr/bin/env python3
"""Setup script for SupwnGo framework."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text() if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
if requirements_path.exists():
    requirements = [
        line.strip()
        for line in requirements_path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
else:
    requirements = []

setup(
    name="supwngo",
    version="1.0.0",
    author="SupwnGo Contributors",
    author_email="supwngo@example.com",
    description="SupwnGo - Automated binary exploitation framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jeremylaratro/supwngo",
    packages=find_packages(exclude=["tests", "tests.*", "build*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Disassemblers",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-asyncio>=0.20.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "myst-parser>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "supwngo=supwngo.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "supwngo": [
            "payloads/templates/*.py",
            "data/*.json",
        ],
    },
    zip_safe=False,
    keywords=[
        "pwn",
        "exploit",
        "binary",
        "security",
        "ctf",
        "rop",
        "shellcode",
        "fuzzing",
        "vulnerability",
    ],
    project_urls={
        "Bug Reports": "https://github.com/jeremylaratro/supwngo/issues",
        "Source": "https://github.com/jeremylaratro/supwngo",
    },
)
