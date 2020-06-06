# Cryptographic Birthday Attack on CBC

### Charles Marshall & Bruno Lehouque

## Program instructions

- To compile:

`make clean`

`make`

Using `make clean` first is mandatory, otherwise the constants may not be
correctly initialized.

- Programs:

 - to put a random 128 bit key in a file

   `./generate_key <key file>`

 - to check non-determinism and correct encryption/decryption

   `./verif [--verbose] <key file> <text file>`

 - to launch N birthday attacks on CBC (default N = 1)

   `./attack [--verbose] [-n N] <key file> <text file>`

Please read the [report](/Report.pdf) for additional information, and analysis of tests. 
