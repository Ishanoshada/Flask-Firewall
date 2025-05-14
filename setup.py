# setup.py
import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="flask_firewall",
    version="0.1.0",
    author="Ishan Oshada",
    author_email="ic31908@gmail.com",
    description="A comprehensive firewall middleware for Flask applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Ishanoshada/flask_firewall",
    license="MIT",
    packages=setuptools.find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Framework :: Flask",
        "Intended Audience :: Developers",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "Flask>=2.0.0",
        "requests>=2.25.0",
        "pytz>=2021.1",
    ],
    keywords="flask firewall security waf recaptcha rate-limiting xss",
)