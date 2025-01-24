# Python version 3.9 or later

import os


# This is a helper function that returns the length of the input N in bytes.
#
# The cryptographically secure randomness generator, os.urandom, takes as input an
# integer 'size' and outputs 'size' random bytes. These bytes can be interpretted as an
# integer between 0 and 256**size - 1 (both inclusive).
#
# To sample a random number between 0 and N, we compute 'size' so that 256**size is the
# smallest power of 256 greater than or equal to N.
def num_rand_bytes(N):
    return (N.bit_length() + 7) // 8


# Alice's random number generator
def alice_rand_gen(N):
    num_bytes = num_rand_bytes(N)

    # Initialize with a sentinel so that at least one iteration of the loop is run.
    val = N + 1

    # Keep re-sampling until we obtain a value less that or equal to N.
    while val > N:
        # Get securely generated random bytes.
        random_bytes = os.urandom(num_bytes)
        # Convert the bytestring returned by os.urandom to an integer.
        val = int.from_bytes(random_bytes, "big")

    return val


# Bob's random number generator
def bob_rand_gen(N):
    num_bytes = num_rand_bytes(N)

    # Get securely generated random bytes.
    random_bytes = os.urandom(num_bytes)

    # Convert the bytestring returned by os.urandom to an integer and reduce it modulo
    # (N+1) to obtain a value between 0 and N.
    val = int.from_bytes(random_bytes, "big") % (N + 1)

    return val
