from copy import copy
from sage.all import QQ, PolynomialRing, RealBallField, ComplexBallField
from proba_util import binomial, law_product, law_convolution


def cbd(eta):
    return {i: QQ(binomial(2 * eta, i + eta)) / 2**(2 * eta)
            for i in range(-eta, eta + 1)}


def compress(x, q, bits):
    return ((2 * (x % q) * (1 << bits) + q) // (2 * q)) % (1 << bits)


def decompress(x, q, bits):
    return (2 * q * x + (1 << bits)) // (2 << bits)


def rounding_law(q, bits):
    """Exact error probabilities for uniform input residues; errors are not uniform."""
    counts = {}
    for x in range(q):
        e = (decompress(compress(x, q, bits), q, bits) - x) % q
        if e > q // 2:
            e -= q
        counts[e] = counts.get(e, 0) + 1
    return {e: QQ(count) / q for e, count in counts.items()}


def as_polynomial(law, ring):
    offset = min(law)
    return ring([law.get(i, 0) for i in range(offset, max(law) + 1)]), offset


def p2_cyclotomic_final_error_distribution(ps, precision=768):
    for levels in (ps.rqk, ps.rqc, ps.rq2):
        if levels < 2 or levels & (levels - 1):
            raise ValueError("Compression levels must be powers of two")
    chis = cbd(ps.ks)
    chie = cbd(ps.ke_ct)
    chie_pk = cbd(ps.ke)
    Rk = rounding_law(ps.q, ps.rqk.bit_length() - 1)
    Rc = rounding_law(ps.q, ps.rqc.bit_length() - 1)
    chiRs = law_convolution(chis, Rk)
    chiRe = law_convolution(chie, Rc)
    B1 = law_product(chie_pk, chiRs)
    B2 = law_product(chis, chiRe)

    ring = PolynomialRing(ComplexBallField(precision), "x")
    p1, o1 = as_polynomial(B1, ring)
    p2, o2 = as_polynomial(B2, ring)
    C1 = p1**(ps.m * ps.n)
    C2 = p2**(ps.m * ps.n)
    C = C1 * C2
    R2 = rounding_law(ps.q, ps.rq2.bit_length() - 1)
    F = law_convolution(R2, chie)
    p3, o3 = as_polynomial(F, ring)
    D = C * p3
    offset = (o1 + o2) * ps.m * ps.n + o3
    result = {}
    for index, probability in enumerate(D.list()):
        result[index + offset] = probability.real()
    return result


def p2_cyclotomic_error_probability(ps, precision=768):
    F = p2_cyclotomic_final_error_distribution(ps, precision)
    tail = sum((p for error, p in F.items() if abs(error) >= ps.q // 4),
               RealBallField(precision)(0))
    return F, ps.n * tail


def failure_probability(ps, precision=768):
    """Bound failures with independent rounding errors from uniform input residues."""
    F, delta = p2_cyclotomic_error_probability(ps, precision)
    ball = RealBallField(precision)
    tails = [ball(0), ball(0)]
    for error, probability in F.items():
        for bit in (0, 1):
            if compress(decompress(bit, ps.q, 1) + error, ps.q, 1) != bit:
                tails[bit] += probability
    upper = delta.upper()
    lower = delta.lower()
    if lower <= 0 or float((upper - lower) / lower) > 2.0**-32:
        raise ArithmeticError("Failure enclosure is too wide; increase precision")
    return {
        "n": ps.n, "k": ps.m, "eta1": ps.ks, "eta2": ps.ke_ct, "q": ps.q,
        "ke": ps.ke, "rqk": ps.rqk,
        "du": ps.rqc.bit_length() - 1, "dv": ps.rq2.bit_length() - 1,
        "precision": precision,
        "log2_delta_lower": float(lower.log2()),
        "log2_delta_upper": float(upper.log2()),
        "delta_upper": str(upper),
        "relative_enclosure_width": str((upper - lower) / lower),
        "log2_p0": float(tails[0].upper().log2()),
        "log2_p1": float(tails[1].upper().log2()),
        "log2_exact_decoding_union_bound": float((ps.n * max(t.upper() for t in tails)).log2()),
        "support": [int(min(F)), int(max(F))],
        "method": "n * Pr[abs(E)>=floor(q/4)]; Arb; full support; independent rounding model",
    }


def select_compression(ps, max_log2_delta, precision=768):
    """Return the first passing encoding in ciphertext-size order."""
    width = (ps.q - 1).bit_length()
    pairs = sorted(((du, dv) for du in range(min(10, width), width + 1)
                    for dv in range(3, min(8, width) + 1)),
                   key=lambda pair: (ps.m * pair[0] + pair[1], pair))
    for du, dv in pairs:
        candidate = copy(ps)
        candidate.rqc, candidate.rq2 = 2**du, 2**dv
        result = failure_probability(candidate, precision)
        if result["log2_delta_upper"] <= max_log2_delta:
            return result
    raise ArithmeticError("No compression choice meets the failure budget")
