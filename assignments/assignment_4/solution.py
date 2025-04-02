"""
Solution to Assignment 4

Python version 3.9 or later.

Your final submission must contain the following functions:
    - compute_ecdsa_sk(params)
    - modify_user_storage(params)

You might require the following packages to implement your solution:
    - pycryptodome: Install by running `pip install pycryptodome`.
    - tinyec: Install by running `pip install tinyec`.
    - dissononce: Install by running `pip install dissononce`.
See 'problem.py' for usage examples.
"""


def compute_ecdsa_sk(params):
    """
    Recovers the server's ECDSA secret key.

    Parameters:
        params (AttackParams): An instance of AttackParams (defined in 'problem.py').

    Returns:
        int: The recovered ECDSA secret key.
    """
    return 0


def modify_user_storage(params, target_data):
    """
    Modify the registered user's storage.

    Parameters:
        params (AttackParams): An instance of AttackParams (defined in 'problem.py').

        target_data (bytes): The user's storage should be set to this byte string at the end of the
            attack.

    Returns: No return value.
    """
    pass
