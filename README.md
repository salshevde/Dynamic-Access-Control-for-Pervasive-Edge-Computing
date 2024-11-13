# Dynamic-Access-Control-for-Pervasive-Edge-Computing
Implementation of Key-Aggregate-Cryptosystem for Dynamic Access Control Dynamic Access Control for Pervasive Edge Computing Devices.

## Prerequisites

Ensure the following libraries are installed on your system:
- PBC (Pairing-Based Cryptography)
- OpenSSL (`libssl`)
- GMP (GNU Multiple Precision Arithmetic Library)
- PARI/GP library

## Compilation and Execution

### Run

To compile and run the main executable:

```bash
gcc main.c -lpbc -lssl -lcrypto -lgmp -lpari
./a.out
```
### Run and Debug w/ GDB

To compile, run and debug using gdb:

```bash
gcc main.c -lpbc -lssl -lcrypto -lgmp -lpari -g
gdb ./a.out
```

