#!/usr/bin/env python3

"""
Assignment 2

Python version 3.9 or later.

Overview:
    This file implements the assignment challenge along with a test harness.
    You do NOT need to modify this file; instead, add your solutions to 'solution.py'.

Required Packages:
    - pycryptodome: Install by running `pip install pycryptodome`.
    The documentation is available at https://www.pycryptodome.org/.
    You only need this package to run the script; it is not required for implementing your solutions.

Usage:
    To verify your solutions, run: `python problem.py`.
    (Make sure that both `solution.py` and `problem.py` are in the same directory.)
"""

from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Random import random, get_random_bytes

import solution


AES_BLOCK_SIZE = 16


# ========================== Problem 1: Padding Oracle Attack ==========================


class PaddingOracleProblem:
    # Create a server that receives ciphertexts, decrypts it and checks padding.
    @staticmethod
    def create_server(key):
        # The server receives a bytestring as input.
        def server(ctx):
            # The first block of the ciphertext is the IV.
            iv = ctx[:AES_BLOCK_SIZE]
            # Decrypt the remaining blocks of the message.
            aes = AES.new(key, AES.MODE_CBC, iv=iv)
            raw_msg = aes.decrypt(ctx[AES_BLOCK_SIZE:])

            try:
                # Attempt to unpad the decrypted message.
                # An error is thrown if the padding is invalid.
                Padding.unpad(raw_msg, AES_BLOCK_SIZE, "pkcs7")
            except:
                # In case of invalid padding, return False.
                return False

            # The padding on the decrypted message was valid.
            return True

        return server

    # Create a server and test it against the submitted solution in `solution.py`.
    @staticmethod
    def test():
        # Genreate key and IV as random bytes.
        #
        # For debugging, you might find it helpful to make the encryption deterministic.
        # You can set the key, IV and msg to a fixed value to do so.
        # For example: `key = b"YELLOW SUBMARINE"` (or any other 16 byte string)
        key = get_random_bytes(AES_BLOCK_SIZE)
        iv = get_random_bytes(AES_BLOCK_SIZE)
        aes = AES.new(key, AES.MODE_CBC, iv=iv)

        # Note that msg_len is set to 10 as an example here. Your solution will be tested
        # against messages of different lengths.
        msg_len = 10
        msg = get_random_bytes(msg_len)

        # Pad and encrypt the message.
        pad_msg = Padding.pad(msg, AES_BLOCK_SIZE, "pkcs7")
        ctx = iv + aes.encrypt(pad_msg)

        # Create the server and run the attack.
        server = PaddingOracleProblem.create_server(key)
        guess = solution.solve_padding_oracle(ctx, server)

        score = 0
        if guess == msg:
            score = 100

        return score


# ======================== Problem 2: Stateful CBC Encryption ==========================


class StatefulCBCProblem:
    # Create a 'compromised device' that receives a message and returns the ciphertext.
    @staticmethod
    def create_compromised_device():
        # Generate cookie.
        #
        # Note that cookie_len is set to 5 as an example here. Your solution will be
        # tested against cookies of different lengths.
        cookie_len = 5
        cookie = get_random_bytes(cookie_len)

        # Sample random key, iv and create a new AES instance.
        key = get_random_bytes(AES_BLOCK_SIZE)
        iv = get_random_bytes(AES_BLOCK_SIZE)
        aes = AES.new(key, AES.MODE_CBC, iv=iv)

        def device(path):
            # Create the message to be encrypted.
            msg = b"".join([path, b";cookie=", cookie])

            # Pad the message. This is just to ensure that there are no errors when
            # messages are not multiples of the block length.
            pad_msg = Padding.pad(msg, AES_BLOCK_SIZE, "pkcs7")

            # Encrypt the padded message.
            #
            # Note that we use the same AES instance every time. This uses the last
            # block of the previous ciphertext when encrypting the current message.
            #
            # More precisely, the pycryptodome API ensures the following:
            # key = get_random_bytes(AES_BLOCK_SIZE)
            # iv = get_random_bytes(AES_BLOCK_SIZE)
            # msg1 = b"YELLOW SUBMARINE"
            # msg2 = b"DR MATTHEW GREEN"
            #
            # aes1 = AES.new(key, AES.MODE_CBC, iv)
            # ctx = aes1(msg1 + msg2)
            #
            # aes2 = AES.new(key, AES.MODE_CBC, iv)
            # ctx1 = aes2.encrypt(msg1)
            # ctx2 = aes2.encrypt(msg2)
            #
            # ctx1 + ctx1 == ctx
            ctx = aes.encrypt(pad_msg)
            return ctx

        return cookie, device

    @staticmethod
    def test_cookie_length():
        cookie, device = StatefulCBCProblem.create_compromised_device()

        guess = solution.find_cookie_length(device)

        score = 0
        if guess == len(cookie):
            score = 100

        return score

    @staticmethod
    def test():
        cookie, device = StatefulCBCProblem.create_compromised_device()

        guess = solution.find_cookie(device)

        score = 0
        if guess == cookie:
            score = 100

        return score


if __name__ == "__main__":
    scores = [
        PaddingOracleProblem.test(),
        StatefulCBCProblem.test_cookie_length(),
        StatefulCBCProblem.test(),
    ]

    print("--- Scores ---")
    print(f"Padding oracle attack: {scores[0]:.2f}")
    print(f"Finding cookie length: {scores[1]:.2f}")
    print(f"Finding cookie: {scores[2]:.2f}")
