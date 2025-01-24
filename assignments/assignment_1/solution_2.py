# Python version 3.9 or later

# Complete the functions below and include this file in your submission.
#
# You can verify your solution by running `problem_2.py`. See `problem_2.py` for more
# details.

# ------------------------------------- IMPORTANT --------------------------------------
# Do NOT modify the name or signature of the three functions below. You can, however,
# add any additional functons to this file.
# --------------------------------------------------------------------------------------

# Given a ciphertext enciphered using the Caesar cipher, recover the plaintext.
# In the Caesar cipher, each byte of the plaintext is XORed by the key (which is a
# single byte) to compute the ciphertext.
#
# The input `ciphertext` is a bytestring i.e., it is an instance of `bytes`
# (see https://docs.python.org/3.9/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview).
# The function should return the plaintext, which is also a bytestring.
def break_caesar_cipher(ciphertext):
    # TODO: Update the body to compute the plaintext
    return b''


# Given a ciphertext enciphered using a Vigenere cipher, find the length of the secret
# key using the 'index of coincidence' method.
#
# The input `ciphertext` is a bytestring.
# The function returns the key length, which is an `int`.
def find_vigenere_key_length(ciphertext):
    # TODO: Update the body to find the key length
    return 0


# Given a ciphertext enciphered using a Vigenere cipher and the length of the key, 
# recover the plaintext.
#
# The input `ciphertext` is a bytestring.
# The function should return the plaintext, which is also a bytestring.
def break_vigenere_cipher(ciphertext, key_length):
    # TODO: Update the body to compute the plaintext
    return b''
