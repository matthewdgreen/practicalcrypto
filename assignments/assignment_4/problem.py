import os
import hashlib
from datetime import datetime
import json
from tinyec.registry import get_curve
from Crypto.Cipher import AES
from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH, PrivateKey
from dissononce.hash.sha512 import SHA512Hash

import solution

"""
Assignment 4

Python version 3.9 or later.

Overview:
    This file implements the assignment problem along with a test harness.
    You do NOT need to modify this file; instead, add your solutions to 'solution.py'.

Required Packages:
    - pycryptodome: Install by running `pip install pycryptodome`.
    - tinyec: Install by running `pip install tinyec`.
    - dissononce: Install by running `pip install dissononce`.

Usage:
    To verify your solutions, run: `python problem.py`.
    (Make sure that both `solution.py` and `problem.py` are in the same directory.)
"""

####################################################################################################
# ECDSA
####################################################################################################
class ECDSA:
    # Create an ECDSA instance using a secret key.
    # Required only to compute signatures since verification is a static method.
    def __init__(self, sk):
        self.sk = sk
        # Randomness required for signatures is sampled using AES in counter mode
        self.rgen = AES.new(os.urandom(16), AES.MODE_ECB)

    # Hash a bytestring into an integer that is in {0, ..., N-1} where N is the order of the
    # elliptic curve
    @staticmethod
    def hash_msg_to_int(message, N):
        return int.from_bytes(hashlib.sha256(message).digest(), "big") % N

    def sign(self, message):
        # Use the P256 curve
        curve = get_curve("secp256r1")
        # N is the order of the group
        N = curve.field.n

        e = ECDSA.hash_msg_to_int(message, N)

        #####################
        # Point of Interest #
        #####################
        while True:
            # Generate 256 bits using AES
            rbyte = os.urandom(1)
            # Convert to integer and valid exponent for the elliptic curve
            k = int.from_bytes(self.rgen.encrypt(rbyte + 15 * b"0" + rbyte + 15 * b"1"), "big") % N
            if k == 0:
                continue

            R = k * curve.g
            r = R.x % N
            if r == 0:
                continue

            k_inv = pow(k, -1, N)
            s = (r * self.sk) % N
            s = (s + e) % N
            s = (s * k_inv) % N

            return (r, s)

    @staticmethod
    def verify(pk, message, signature):
        curve = get_curve("secp256r1")
        N = curve.field.n

        (r, s) = signature

        if not (1 <= r < N and 1 <= s < N):
            return False

        e = ECDSA.hash_msg_to_int(message, N)
        s_inv = pow(s, -1, N)
        u1 = (e * s_inv) % N
        u2 = (r * s_inv) % N

        R = (u1 * curve.g) + (u2 * pk)

        if R.x % N == r:
            return True
        return False


####################################################################################################
# Noise Protocol
####################################################################################################
# This is a simplified version of the HandShakeState class from the dissononce package, tailored to
# implement only the Noise protocol K-pattern. While the dissononce package supports the K-pattern,
# solving the assignment may require slight modifications to how handshake messages are computed,
# and the simplified version provided here should be much easier to work with.
#
# You do not need to be familiar with the lower level details of the cryptographic functions---
# namely, CipherState, SymmetricState, and DH---used in this implementation. A high-level overview
# of their functionality (including the description of each method they support) can be found in
# the Noise protocol specification (https://noiseprotocol.org/noise.html#crypto-functions).
class KHandShakeState:
    def __init__(self, symmetricstate, dh):
        # symmatricstate (which is an instance of SymmetricState) maintains a chaining key
        # and a hash of the complete handshake transcript. The chaining key is used to encrypt the
        # handshake messages.
        self.symmetricstate = symmetricstate
        # dh (an instance of DH) helps computed Diffie-Hellman key exchange
        self.dh = dh
        # Static keypair
        self.s = None
        # Ephemeral keypair
        self.e = None
        # Remote static public key
        self.rs = None
        # Remote ephemeral public key
        self.re = None
        # Denotes if this instance is the initiator or the responder in the handshake
        self.initiator = None
        # The protocol name summarizes the Noise protocol pattern and the cryptographic functions
        # used for the handshake. These are hardcoded for the purpose of this assignment to keep
        # things simple.
        self.protocol_name = "Noise_K_25519_ChaChaPoly_SHA256"

    # Initialize the instance
    # This method should be called after creating the instance and before reading or writing
    # messages.
    def initialize(self, initiator, s=None, e=None, rs=None, re=None):
        # Initialize symmetricstate (see specification for more details)
        self.symmetricstate.initialize_symmetric(self.protocol_name.encode())

        # Prologue
        # The prologue allows the hash of arbitrary data to be included in the computation of the
        # chaining key; often to capture prior context. See https://noiseprotocol.org/noise.html#prologue
        # for more details.
        prologue = b""
        self.symmetricstate.mix_hash(prologue)

        self.initiator = initiator
        self.s = s
        self.e = e
        self.rs = rs
        self.re = re

        # Process pre-messages
        # For the K pattern, the pre-messages includes the static public-keys of the initiator and
        # responder.
        if initiator:
            # mix_hash updates the hash of the transcript of the handshake.
            # See https://noiseprotocol.org/noise.html#the-symmetricstate-object
            self.symmetricstate.mix_hash(s.public.data)

            assert rs is not None, "a pre_message required rs but was empty"
            self.symmetricstate.mix_hash(rs.data)
        else:
            assert rs is not None, "a pre_message required rs but was empty"
            self.symmetricstate.mix_hash(rs.data)

            self.symmetricstate.mix_hash(s.public.data)

    # Writes the initiator' handshake message into message_buffer.
    # message_buffer is of type bytearray.
    def write_message(self, payload, message_buffer):
        assert self.initiator, "responder has no handshake message"

        # The handshake for the K-pattern is: e, es, ss.
        # We process each token sequentially.

        # Pattern token: e
        # Create an ephemeral key and include it in the message.
        self.e = self.dh.generate_keypair()
        message_buffer.extend(self.e.public.data)
        self.symmetricstate.mix_hash(self.e.public.data)

        # Pattern token: es
        # Compute the key es by performing DH key agreement on e and rs.
        # The resulting key is used to update the chaining key using mix_key.
        # See https://noiseprotocol.org/noise.html#the-symmetricstate-object
        self.symmetricstate.mix_key(self.dh.dh(self.e, self.rs))

        # Pattern token: es
        # Same as above but compute the key ss by performing DH key agreement on s and rs.
        self.symmetricstate.mix_key(self.dh.dh(self.s, self.rs))

        # Encrypt payload
        # Finalize the message by encrypting and authenticating the transcript and payload.
        message_buffer.extend(self.symmetricstate.encrypt_and_hash(payload))

    # Reads the initiator' handshake message and writes the decrypted payload into payload_buffer.
    # Called by the responder.
    # payload_buffer is of type bytearray.
    def read_message(self, message, payload_buffer):
        assert not self.initiator, "initiator can't read handshake message"

        # As in the case of write_message, we process each token sequentially.

        # Pattern token: e
        self.re = self.dh.create_public(message[: self.dh.dhlen])
        self.symmetricstate.mix_hash(self.re.data)
        message = message[self.dh.dhlen :]

        # Pattern token: es
        self.symmetricstate.mix_key(self.dh.dh(self.s, self.re))

        # Pattern token: ss
        self.symmetricstate.mix_key(self.dh.dh(self.s, self.rs))

        # Decrypt payload
        payload_buffer.extend(self.symmetricstate.decrypt_and_hash(message))


####################################################################################################
# Problem
####################################################################################################
# Cloud storage server
# Instances of this class are meant to emulate the cloud storage server for the purpose of this
# assignment. To keep things simple, the implementation supports only a single registered user.
class Server:
    def __init__(self):
        curve = get_curve("secp256r1")

        #####################
        # Point of Interest #
        #####################
        # Generate ECDSA keypair and static DH keypair for handshake
        sk = os.urandom(16)
        self.ecdsa_sk = int.from_bytes(sk, "big") % curve.field.n
        self.ecdsa_pk = self.ecdsa_sk * curve.g
        self.static_sk = PrivateKey(sk + b"0" * 16)

        self.ecdsa = ECDSA(self.ecdsa_sk)
        self.static_keypair = X25519DH().generate_keypair(self.static_sk)

        # Used to store client data
        self.db = None
        # Stores the static public key of the (single) registered user
        self.user_static_pk = None

    def get_ecdsa_pk(self):
        return self.ecdsa_pk

    def get_static_pk(self):
        return self.static_keypair.public

    def get_user_storage(self):
        return self.db

    def register_user(self, user_pk):
        self.user_static_pk = user_pk

    # Service provided by the server so that users can check for software updates.
    # The server signs the status message to authenticate itself to the users.
    def check_update(self):
        message = json.dumps(
            {"time": datetime.now().isoformat(), "status": "No update"}
        ).encode()

        return message, self.ecdsa.sign(message)

    # Service provided by the server so that registered users can securely update their cloud
    # storage data
    def update_storage(self, msg):
        # Perform handshake to decrypt payload
        responder = KHandShakeState(
            SymmetricState(CipherState(ChaChaPolyCipher()), SHA512Hash()), X25519DH()
        )
        responder.initialize(False, s=self.static_keypair, rs=self.user_static_pk)

        payload = bytearray()

        try:
            # This will fail if the handshake message is malformed e.g., when the client is not
            # registered
            responder.read_message(msg, payload)
            # If handshake is successful, update the storage with the plaintext payload
            self.db = bytes(payload)
        except:
            print("Malformed upload request")


# Client that creates a message for updating storage
#
# The function takes the registered user's static key pair and the cloud storage server's static
# public key. While the implementation is simplified for the assignment, the server's static public
# key (as well as its ECDSA verification key) can be shipped with the client software while the
# user generates it's static public key with the server during registration.
def client(keypair, server_static_pk):
    initiator = KHandShakeState(
        SymmetricState(CipherState(ChaChaPolyCipher()), SHA512Hash()), X25519DH()
    )
    initiator.initialize(True, s=keypair, rs=server_static_pk)

    data = b"super secret file"
    msg = bytearray()
    initiator.write_message(data, msg)

    return bytes(msg)


# A utility class to pass relevant information to functions in solution.py
class AttackParams:
    def __init__(self, client_keypair, server):
        self.client_static_pk = client_keypair.public
        self.server_static_pk = server.get_static_pk()
        self.get_client_handshake_message = lambda: client(
            client_keypair, self.server_static_pk
        )
        self.check_update = server.check_update
        self.update_storage = server.update_storage


if __name__ == "__main__":
    # Create server
    server = Server()
    server_static_pk = server.get_static_pk()

    # Generate user's static key pair and register the user
    client_keypair = X25519DH().generate_keypair()
    server.register_user(client_keypair.public)

    # An example where the registered user first checks for updates and then updates its cloud
    # storage. Included as an example for using the server's services.
    # print("--- Check Update ---")
    # status_msg, sig = server.check_update()
    # status = json.loads(status_msg.decode('utf-8'))["status"]
    # sig_verif_status = ECDSA.verify(server.get_ecdsa_pk(), status_msg, sig)
    # print(f"Signature verification successful: {sig_verif_status}")
    # print(f"Status: {status}")
    # print("\n--- Update Storage ---")
    # print(f"Old cloud storage data: {server.get_user_storage()}")
    # msg = client(client_keypair, server_static_pk)
    # server.update_storage(msg)
    # print(f"Updated cloud storage data: {server.get_user_storage()}")

    # An example where an unregistered user attempts to update cloud storage.
    # print("--- Unregistered User Updates Storage ---")
    # # Generate new static keypair for the handshake
    # keypair = X25519DH().generate_keypair()
    # msg = client(keypair, server_static_pk)
    # server.update_storage(msg)

    params = AttackParams(client_keypair, server)
    # Computing ECDSA secret key
    guess_sk = solution.compute_ecdsa_sk(params)
    ecdsa_sk_score = 100 if guess_sk == server.ecdsa_sk else 0
    # Modifying registered user's storage
    target_data = b"Use ThreeDrive instead!"
    solution.modify_user_storage(params, target_data)
    modify_storage_score = 100 if server.get_user_storage() == target_data else 0

    print("--- Scores ---")
    print(f"Compute ECDSA secret key: {ecdsa_sk_score}")
    print(f"Modify user storage: {modify_storage_score}")
