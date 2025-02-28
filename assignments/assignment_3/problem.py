#!/usr/bin/env python3
import random
import sys
from functools import reduce

import solution

"""
Assignment 3

Python version 3.9 or later.

Overview:
    This file implements the assignment challenge along with a test harness.
    You do NOT need to modify this file; instead, add your solutions to 'solution.py'.

Usage:
    To verify your solutions, run: `python problem.py <param_type=tiny | small | medium>`.
    (Make sure that both `solution.py` and `problem.py` are in the same directory.)
    param_type denotes the set of parameters used for the test (see end of script).
"""

# ============================================ Utils  =============================================
class Params:
    """A class used to store parameter values, subsequently used in tests.

    Attributes:
        - mod: Prime number used as modulus
        - factors: A list of the form [(p_1, e_1), ..., (p_n, e_n)] such that
            P - 1 = p_1^{e_1} * ... * p_n^{e_n}.
        - gen: Generator for Z_mod.
        - exp_bound: The secret key or exponent is sampled at random from the set
            {0, ..., exp_bound - 1}.
    """

    def __init__(self, mod, factors, gen, exp_bound):
        self.mod = mod
        self.factors = factors
        self.gen = gen
        self.exp_bound = exp_bound


# ========================== Problem 1.a: Brute Force Discrete Log  ===============================
class BruteForceDL:
    @staticmethod
    def test(mod, sub_grp_gen, sub_grp_order):
        s = random.randint(0, sub_grp_order - 1)
        val = pow(sub_grp_gen, s, mod)

        guess = solution.brute_force_dl(mod, sub_grp_gen, sub_grp_order, val)

        score = 0
        if guess % sub_grp_order == s:
            score = 100

        return score


# ====================== Problem 1.b: Baby Step Giant Step Discrete Log  ==========================
class BabyStepGiantStepDL:
    @staticmethod
    def test(mod, sub_grp_gen, sub_grp_order):
        s = random.randint(0, sub_grp_order - 1)
        val = pow(sub_grp_gen, s, mod)

        guess = solution.baby_step_giant_step_dl(mod, sub_grp_gen, sub_grp_order, val)

        score = 0
        if guess % sub_grp_order == s:
            score = 100

        return score


# ========================== Problem 1.c: Chinese Remainder Theorem  ==============================
class CRT:
    @staticmethod
    def test(vals, mods):
        res = solution.crt(vals, mods)

        for val, mod in zip(vals, mods):
            if res % mod != val:
                return 0

        return 100


# ===================== Problem 1.d: Pohlig-Hellman Prime Power ===================================
class PohligHellman:
    @staticmethod
    def test(mod, sub_grp_gen, sub_grp_order_factors):
        sub_grp_order = reduce(
            lambda acc, x: acc * x[0] ** x[1], sub_grp_order_factors, 1
        )
        s = random.randint(0, sub_grp_order - 1)
        val = pow(sub_grp_gen, s, mod)

        guess = solution.pohlig_hellman(mod, sub_grp_gen, sub_grp_order_factors, val)

        score = 0
        if guess % sub_grp_order == s:
            score = 100

        return score


# =========================== Problem 1.e: ElGamal Attack =========================================
class ElGamalAttack:
    @staticmethod
    def test(params):
        sk = random.randint(0, params.exp_bound - 1)
        pk = pow(params.gen, sk, params.mod)

        guess = solution.elgamal_attack(params, pk)

        score = 0
        if guess % (params.mod - 1) == sk:
            score = 100

        return score


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <param_type=tiny | small | medium>")
        sys.exit()

    param_type = sys.argv[1]

    score_names = [
        "Brute force DL",
        "Baby Step Giant Step DL",
        "Chinese Remainder Theorem",
        "Pohlig-Hellman",
        "ElGamal Attack",
    ]

    scores = []
    # See Param class definition to see what each parameter denotes.
    if param_type == "tiny":
        # Tiny (6-bit prime)
        #   These params are mainly to help debug.
        #   Note that exp_bound is equal to Φ(mod) = mod - 1. This means that the secret key is
        #   sampled uniformly at random from {0, ..., mod - 2}, as in standard ElGamal encryption.
        params = Params(mod=61, factors=[(2, 2), (3, 1), (5, 1)], gen=30, exp_bound=60)

        # Brute force DL
        #   We compute DL over Z*_mod, which can be done efficiently since mod is small.
        scores.append(BruteForceDL.test(params.mod, params.gen, params.mod - 1))

        # Baby Step Giant Step DL
        #   We compute DL over Z*_mod.
        scores.append(BabyStepGiantStepDL.test(params.mod, params.gen, params.mod - 1))

        # CRT
        mods = [x[0] ** x[1] for x in params.factors]
        vals = [random.randint(0, mod - 1) for mod in mods]
        scores.append(CRT.test(vals, mods))

        # Pohlig-Hellman
        #   We compute DL over Z*_mod.
        scores.append(PohligHellman.test(params.mod, params.gen, params.factors))
    elif param_type == "small":
        # Small (130-bit prime)
        #   Observe that exp_bound is equal to Φ(mod) = mod - 1, which means that the secret key
        #   is sampled from a very large set, consisting of ~2^130 values. Moreover, the secret key
        #   space is {0, ..., mod-2}, as in the standard ElGamal encryption scheme.
        #
        #   However, we will be able to recover the secret key (despite it being sampled from a
        #   large set) using Pohlig-Hellman because the order of Z*_mod, namely Φ(mod) = mod - 1,
        #   does not contain any large prime factors.
        params = Params(
            mod=927561315432648769274106771080177774153,
            factors=[(2, 3), (67, 3), (131, 5), (257, 3), (521, 1), (1031, 4)],
            gen=216606503944793770949515456773896502127,
            exp_bound=927561315432648769274106771080177774152,
        )

        # Brute force DL
        #   Contrary to the case of 'tiny' params, brute force is no longer feasible to find the
        #   discrete log over Z*_mod when mod is a 130-bit modulus since this will require iterating
        #   over approximately 2^138 ~ 10^41 values.
        #   Thus, we use a much smaller subgroup in Z*_mod to run the brute force discrete log test.
        exp = 67 * 131**5 * 257**3 * 521 * 1031**4
        # To understand why sub_grp_gen is computed this way:
        #    - See "Subgroups of Cyclic Groups" in https://crypto.stanford.edu/pbc/notes/numbertheory/cyclic.html, or
        #    - Theorem 2.15 in https://shoup.net/ntb/ntb-v2.pdf
        sub_grp_gen = pow(params.gen, exp, params.mod)
        sub_grp_order = (params.mod - 1) // exp  # sub_grp_order = 35,912
        scores.append(BruteForceDL.test(params.mod, sub_grp_gen, sub_grp_order))

        # Baby Step Giant Step DL
        #   Compared to brute force DL, we can compute discrete log over a larger subgroup using the
        #   BSGS algorithm, since it improves the runtime to √sub_grp_order.
        exp = 131**5 * 257**3 * 1031**4
        sub_grp_gen = pow(params.gen, exp, params.mod)
        sub_grp_order = (
            params.mod - 1
        ) // exp  # sub_grp_order = 1,253,580,184, √sub_grp_order = 35,406
        scores.append(BabyStepGiantStepDL.test(params.mod, sub_grp_gen, sub_grp_order))

        # CRT
        mods = [x[0] ** x[1] for x in params.factors]
        vals = [random.randint(0, mod - 1) for mod in mods]
        scores.append(CRT.test(vals, mods))

        # Pohlig-Hellman
        #   As mentioned previously, because the order of the subgroup `mod - 1` does not contain
        #   any large prime factors, we can compute the discrete log for any element in Z*_mod.
        scores.append(PohligHellman.test(params.mod, params.gen, params.factors))
    else:
        # Medium (522-bit prime)
        #   Observe that exp_bound is much smaller than mod - 1, however, the resulting secret key
        #   space is still large, consisting of 2^128 values.
        params = Params(
            mod=7428206452375868051112377676516436620612011672582445792917111703118561592770349740098371912233951285585673180734253488802868241288412306084645060103575110649,
            factors=[(2, 3), (257, 8), (1031, 7), (18446744073709551629, 6)],
            gen=4026924533573022326359046855640747468905899959801793804281259660339223595723025138872101897427591935153581205666098085487298502501358616958443351972709036895,
            exp_bound=2**128,
        )

        # Brute force DL
        #   Once again, we consider a small subgroup in Z*_mod over which we can efficiently brute
        #   force the discrete log.
        exp = 257**6 * 1031**7 * 18446744073709551629**6
        sub_grp_gen = pow(params.gen, exp, params.mod)
        sub_grp_order = (params.mod - 1) // exp  # sub_grp_order = 5,28,392
        scores.append(BruteForceDL.test(params.mod, sub_grp_gen, sub_grp_order))

        # Baby Step Giant Step DL
        #   Since BSGS improves the runtime, we can afford to compute the discrete log over a larger
        #   subgroup of Z*_mod, compared to the brute force computation.
        exp = 257**6 * 1031**6 * 18446744073709551629**6
        sub_grp_gen = pow(params.gen, exp, params.mod)
        sub_grp_order = (params.mod - 1) // exp  # sub_grp_order = 544,772,152
        scores.append(BabyStepGiantStepDL.test(params.mod, sub_grp_gen, sub_grp_order))

        # CRT
        mods = [x[0] ** x[1] for x in params.factors]
        vals = [random.randint(0, mod - 1) for mod in mods]
        scores.append(CRT.test(vals, mods))

        # Pohlig-Hellman
        #   Let p_4 = 18446744073709551629.
        #   Unlike the case of 'small' or 'tiny' parameters, the order of Z*_mod, namely mod - 1,
        #   has a large prime factor p_4. Specifically, since 2^63 < p_4 < 2^64, we cannot compute
        #   the discrete log over any subgroup of Z*_mod such that p_4 divides the order of the
        #   subgroup, since this will require at least √2^64 = 2^32 steps.
        #
        #   Thus, we compute discrete log over a subgroup of Z*_mod such that the order of the
        #   subgroup consists of only small prime factors.
        sub_factors = [(2, 3), (257, 8), (1031, 7)]
        sub_grp_order = reduce(lambda acc, x: acc * x[0] ** x[1], sub_factors, 1)
        sub_grp_gen = pow(params.gen, (params.mod - 1) // sub_grp_order, params.mod)
        scores.append(PohligHellman.test(params.mod, sub_grp_gen, sub_factors))

    # ElGamal Attack
    scores.append(ElGamalAttack.test(params))

    # Output
    print("--- Scores ---")
    for name, score in zip(score_names, scores):
        print(f"{name}: {score:.2f}")
