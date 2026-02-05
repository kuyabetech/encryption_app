"""
Setup script for Secure File Encryption.
"""

from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="secure-encrypt",
    version="1.0.0",
    author="Secure Encryption Team",
    description="Secure file encryption with AES-256-GCM and Argon2",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/secure-encrypt",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Natural Language :: English",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=42.0.0",
        "argon2-cffi>=23.1.0",
        "click>=8.1.0",
    ],
    entry_points={
        "console_scripts": [
            "secure-encrypt=app:main",
            "senc=app:main",
        ],
    },
    include_package_data=True,
    keywords="encryption, security, aes, argon2, file encryption",
)