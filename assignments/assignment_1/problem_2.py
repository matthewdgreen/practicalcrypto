# Python version 3.9 or later


# This file implements the Vigenere cipher and helps run test cases.
#
# You do NOT need to submit nor modify this file. Instead, add your solutions to
# 'solution_2.py'.
#
# To verify your solutions, run: `python problem_2.py sample.json`.
# This will require that 'solution_2.py', 'problem_2.py' and 'sample.json' are in the
# same directory.
#
# Your submission will be graded by running your solution on a number of test cases.
# Scores on 'sample.json' might not imply the same score for the total points awarded.

import solution_2
import json
import sys
import base64


# Enciphers the given plaintext under the input key using Vigenere cipher.
# Both key and plaintext are instances of bytes.
def vigenere_cipher(key, plaintext):
    n = len(key)

    # Encipher the plaintext in chunks of size n
    ciphertext = b""
    for i in range(0, len(plaintext), n):
        # Get the i-th chunk
        chunk = plaintext[i : i + n]
        # XOR the j-th byte of the chunk with the j-th byte of the key
        ciphertext += bytes(chunk[j] ^ key[j] for j in range(len(chunk)))

    return ciphertext


# -------------------- Test Harness --------------------


def score_recovered_plaintext(recovered, plaintext):
    n = len(plaintext)

    if len(recovered) != n:
        return 0

    num_match = sum(map(lambda i: 1 if recovered[i] == plaintext[i] else 0, range(n)))
    percent_match = (num_match * 100.0) / n

    return percent_match


def run_caesar_cipher_test(key, plaintext):
    key = bytes([key[0]])
    ciphertext = vigenere_cipher(key, plaintext)

    recovered = solution_2.break_caesar_cipher(ciphertext)

    return score_recovered_plaintext(recovered, plaintext)


def run_vigenere_key_length_test(key, plaintext):
    ciphertext = vigenere_cipher(key, plaintext)
    answer = len(key)

    guess = solution_2.find_vigenere_key_length(ciphertext)

    score = 0
    if guess == answer:
        score = 100
    elif guess != 0 and guess % answer == 0:
        score = 80

    return score


def run_vigenere_cipher_test(key, plaintext):
    ciphertext = vigenere_cipher(key, plaintext)

    recovered = solution_2.break_vigenere_cipher(ciphertext, len(key))

    return score_recovered_plaintext(recovered, plaintext)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <test_case.json>")
        sys.exit()

    with open(sys.argv[1], "r") as f:
        test_data = json.load(f)

    # The key and plaintext are encoded in base64.
    # Convert them to bytes.
    key = base64.b64decode(test_data["key"])
    plaintext = base64.b64decode(test_data["plaintext"])

    scores = [
        run_caesar_cipher_test(key, plaintext),
        run_vigenere_key_length_test(key, plaintext),
        run_vigenere_cipher_test(key, plaintext),
    ]

    print("---- Scores ---")
    print(f"Breaking Caesar cipher: {scores[0]:.2f}%")
    print(f"Finding Vigenere key length: {scores[1]:.2f}%")
    print(f"Breaking Vigenere cipher: {scores[2]:.2f}%")
