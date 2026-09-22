from copy import copy
from sage.all import is_prime
from Kyber_failure import failure_probability, select_compression
from MLWE_security import estimate
from QROM_security import QROM, account, communication, factors


class KyberParameterSet:
    """Use the official script's parameter names and compression levels."""

    def __init__(self, n, m, ks, ke, q, rqk, rqc, rq2, ke_ct=None):
        self.n = n
        self.m = m
        self.ks = ks
        self.ke = ke
        self.q = q
        self.rqk = rqk
        self.rqc = rqc
        self.rq2 = rq2
        self.ke_ct = ke if ke_ct is None else ke_ct


# Edit these definitions directly, as in the official Kyber.py.
SUITES = {
    128: KyberParameterSet(512, 2, 3, 3, 7681, 2**13, 2**11, 2**4),
    192: KyberParameterSet(512, 3, 2, 2, 7681, 2**13, 2**11, 2**4),
    256: KyberParameterSet(512, 4, 2, 2, 7681, 2**13, 2**12, 2**5),
}
PRECISION = 768


def summarize(ps, target, config=None, precision=PRECISION, failure_only=False,
              search_compression=False, sensitivity=False):

    config = QROM if config is None else config
    if not is_prime(ps.q) or (ps.q - 1) % ps.n:
        raise ValueError("Prime modulus and incomplete-NTT root condition failed")
    if ps.n != config["message_bits"] or ps.n % 8:
        raise ValueError("Require one message bit per coefficient and a byte-aligned degree")
    if ps.rqk != 1 << (ps.q - 1).bit_length():
        raise ValueError("The suite reduction and byte sizes require lossless public keys")
    if search_compression:
        multiplier = factors(config["log2_queries"], config["log2_depth"],
                             config["message_bits"])["log2_failure_multiplier"]
        failure = select_compression(ps,
                                     max_log2_delta=-target-multiplier-2-1e-9,
                                     precision=precision)
        ps = copy(ps)
        ps.rqc, ps.rq2 = 2**failure["du"], 2**failure["dv"]
    else:
        failure = None
    sizes = communication(ps, config)
    print(f"Kyber-QROM-{target}: n={ps.n}, k={ps.m}, q={ps.q}, ks={ps.ks}, ke={ps.ke}, ke_ct={ps.ke_ct}")
    print(f"  rqk={ps.rqk}, rqc={ps.rqc}, rq2={ps.rq2}")
    print(f"  bytes: pk={sizes['public_key_bytes']}, "
          f"ct={sizes['ciphertext_bytes']}, sk={sizes['decapsulation_key_bytes']}, "
          f"shared={sizes['shared_key_bytes']}", flush=True)
    if failure is None:
        failure = failure_probability(ps, precision=precision)
    print(f"  failure (model): 2^{failure['log2_delta_upper']:.3f}", flush=True)
    result = {"parameters": vars(ps).copy(), "communication": sizes, "failure": failure}
    if failure_only:
        return result
    lattice = {model: estimate(ps, model=model) for model in ("classical", "quantum")}
    bound = account(lattice["quantum"]["minimum_bits"], failure["log2_delta_upper"], target, config)
    passed = bound["meets_target_conditionally"] and bound["all_four_terms_have_two_bit_reserve"]
    print(f"  bits: classical={lattice['classical']['minimum_bits']:.2f}, "
          f"quantum={lattice['quantum']['minimum_bits']:.2f}, "
          f"QROM (conditional)={bound['conditional_accounting_bits']:.2f} "
          f"({'PASS' if passed else 'FAIL'})", flush=True)
    if sensitivity:
        print("query sensitivity (log2 queries = log2 depth -> conditional bits):")
        for logq in (32, 48, 64, 80, 96):
            cfg = dict(config, log2_queries=logq, log2_depth=logq)
            score = account(lattice["quantum"]["minimum_bits"], failure["log2_delta_upper"], target, cfg)
            print(f"  {logq:>2} -> {score['conditional_accounting_bits']:.2f}")
    return {**result, "lattice": lattice, "qrom": bound}



passed = True
for target, ps in SUITES.items():
    result = summarize(ps, target, precision=PRECISION)
    passed &= (result["qrom"]["meets_target_conditionally"] and
                result["qrom"]["all_four_terms_have_two_bit_reserve"])
    print(f"Kyber-QROM-{target} {'PASS' if passed else 'FAIL'}", flush=True)
