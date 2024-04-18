<a name="readme-top"></a>

[![Unit Tests](https://github.com/PeterMcQuaid/EtherGuard/actions/workflows/build.yaml/badge.svg)](https://github.com/PeterMcQuaid/EtherGuard/actions/workflows/build.yaml) [![Python Version](https://img.shields.io/badge/python-3.8-blue)](https://www.python.org/downloads/release/python-3815/) [![License](https://img.shields.io/badge/license-MIT-green)](LICENSE) 


<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/PeterMcQuaid/EtherGuard/images">
    <img src="https://raw.githubusercontent.com/PeterMcQuaid/EtherGuard/main/images/logoBlobs.jpg" alt="Logo" width=500>
  </a>

  <h3 align="center">EtherGuard</h3>

  <p align="center">
    A secure and efficient EVM-based wallet
    <br />
    <a href="https://github.com/PeterMcQuaid/EtherGuard#installation"><strong>Setup & Installation »</strong></a>
    <br />
    <br />
    <a href="https://github.com/PeterMcQuaid/EtherGuard#contributions">Contribute to EtherGuard</a>
    ·
    <a href="https://github.com/PeterMcQuaid/EtherGuard/issues">Report Bug</a>
    ·
    <a href="https://github.com/PeterMcQuaid/EtherGuard/issues">Request Feature</a>
  </p>
</div>


## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Project Layout](#project-layout)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributions](#contributions)
- [License](#license)

## Introduction

EtherGuard is a Python-based EVM wallet with arbitrary message signing functionality. EtherGuard creates raw transactions that can be sent to any EVM-compatible chain, via a node's JSON-RPC API

EtherGuard supports all three transaction types across EVM-chains, and has full support for custom access lists

EtherGuard uses the Tonelli-Shanks algorithm for public key recovery from the ECDSA signature generated

## Features

- Now supports EIP-4844 blob transactions
- EVM wallet
- Supports all transaction types
- Supports all EVM-chains
- Supports access lists
- Supports arbitrary message signing
- Supports contract creation

## Project Layout
```
├── LICENSE
├── README.md
├── Tests
│   ├── __init__.py
│   └── test_wallet.py
├── Wallet
│   ├── TonelliShanks.py
│   ├── blob_data.txt
│   └── evm_wallet.py
├── externals
│   └── c-kzg-4844
├── images
│   ├── logo.JPG
│   └── logoBlobs.jpg
├── logs
└── requirements.txt
```

## Prerequisites

- Python 3.8+

## Installation

1. Clone the repository
   ```bash
   git clone --recurse-submodules https://github.com/PeterMcQuaid/EtherGuard.git
   ```
2. Navigate to project directory
   ```
   cd EtherGuard
   ```
3. Install requirements
    ```
   pip install -r requirements.txt
   ```
4. Build the C-KZG-4844 Python bindings:
   ```
   cd EtherGuard/externals/c-kzg-4844/bindings/python/
   make
   ```
5. Append PYTHON_PATH if necessary:
   ```
   export PYTHONPATH="${PYTHONPATH}:/path/to/your/project/submodule/python_bindings"
   ```

## Usage

1. Set PRIVATE_KEY environment varible
    ```
    touch .env
    //add private key
    source .env
    ```
    Note - Storing a private key as an environment variable is NOT secure and should never be used to store real funds

2. Create a signed transaction
    ```
    python ./Wallet/evm_wallet.py
    ```

3. Sign an arbitrary message
    ```
    python ./Wallet/evm_wallet.py signMessage "arbitrary message"
    ```
    
## Testing
    
1. Run unit-tests in root directory 
    ```
    pytest
    ```
    
## Legal Disclaimer
  
  Please note that EtherGuard is intended for educational and demonstration purposes. The author is not responsible for any loss of funds or other damages caused by the use of this wallet. Always ensure you have backups of your keys and use this software at your own risk
  
## Contributions

Pull requests are welcome! Please ensure that any changes or additions you make are well-documented and covered by test cases.

For any bugs or issues, please open an [issue](https://github.com/PeterMcQuaid/EtherGuard/issues).

  
## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details
