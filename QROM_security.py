import math

QROM = {
    "log2_queries": 64,          # lg(Q): total oracle queries; Q is not modulus q.
    "log2_depth": 64,            # lg(D): sequential query depth, D <= Q.
    "message_bits": 512,         # b_msg: encoded message length.
    "key_bits": 512,             # Shared KEM key length.
    "coins_seed_bits": 512,      # Encryption-coins seed; metadata here.
    "rejection_seed_bits": 512,  # Implicit-rejection seed stored in the secret key.
    "keygen_seed_bits": 512,     # Key-generation seed; metadata here.
    "matrix_seed_bits": 512,     # Public matrix seed stored in the public key.
    "public_key_hash_bits": 512, # Hash of the public key stored in the secret key.
    "assumed_prf_advantage_bits": 320,
    "log2_decap_queries": 64,    # Decapsulation-query budget; metadata here.
    "runtime_loss_bits": 0,     # Accumulator for the total security loss.
}


def log2_sum(*lg_vals):
    """Return lg(sum(2**x)); inputs are logarithms, not probabilities."""
    lg_max = max(lg_vals)  # Shift by the largest exponent for numerical stability.
    if lg_max == -math.inf:
        return lg_max
    return lg_max + math.log2(math.fsum(2.0**(lg_x - lg_max) for lg_x in lg_vals))


def factors(lg_q, lg_d, b_msg):
    """Reduction factors for lg(Q) queries, lg(D) depth, and b_msg message bits."""
    if not 0 <= lg_d <= lg_q or b_msg < 1:
        raise ValueError("Require 1 <= depth <= total queries and a nonempty message space")
    lg_sqrt = 0.5 * (lg_d + log2_sum(math.log2(7) + lg_d, math.log2(3)))  # lg(sqrt(D(7D+3))).
    return {
        "lg_lat_mult": 2 + lg_sqrt,  # lg(4 sqrt(D(7D+3))); lattice multiplier.
        "lg_df_mult": log2_sum(4 + 2 * log2_sum(2 + lg_q, 0),
                                            2 + lg_d / 2),  # lg(16(4Q+1)^2 + 4 sqrt(D)).
        "lg_space": 4 + lg_sqrt + log2_sum(3 + lg_q, 0) - b_msg,
        # Last term: lg(16 sqrt(D(7D+3)) (8Q+1) / 2**b_msg).
    }


def account(b_lat, lg_df, b_tgt, cfg):
    red = factors(cfg["log2_queries"], cfg["log2_depth"], cfg["message_bits"])  # Reduction factors.
    lg_adv = {  # Base-2 logarithms of the four advantage contributions.
        "lattice": red["lg_lat_mult"] + cfg["runtime_loss_bits"] - b_lat,
        "failure": red["lg_df_mult"] + lg_df,
        "prf_assumption": -cfg["assumed_prf_advantage_bits"],
        "finite_space": red["lg_space"],
    }
    b_sec = -log2_sum(*lg_adv.values())  # Conditional security exponent of the total advantage.
    b_req = b_tgt + 2  # Four terms <= 2**(-b_req) sum to at most 2**(-b_tgt).
    return {
        **red,
        "lg_adv": lg_adv,
        "b_lat_adj": -lg_adv["lattice"],
        "b_df_adj": -lg_adv["failure"],
        "b_qrom": b_sec,
        "b_tgt": b_tgt,
        "target_ok": b_sec >= b_tgt,
        "reserve_ok": all(lg_eps <= -b_req for lg_eps in lg_adv.values()),
        "b_lat_req": b_req + red["lg_lat_mult"] + cfg["runtime_loss_bits"],
        "b_df_req": b_req + red["lg_df_mult"],
        "b_prf_req": b_req,
        "b_msg_req": math.ceil(cfg["message_bits"] + red["lg_space"] + b_tgt + 2),
    }


def communication(ps, cfg):
    n, k, q = ps.n, ps.m, ps.q  # Polynomial degree, module rank, coefficient modulus.
    d_pk = (q - 1).bit_length()  # Bits per losslessly encoded key coefficient.
    d_u = ps.rqc.bit_length() - 1  # Bits per ciphertext-vector coefficient.
    d_v = ps.rq2.bit_length() - 1  # Bits per ciphertext-scalar coefficient.
    sk_pke_bytes = n * k * d_pk // 8  # PKE secret vector, before KEM fields.
    pk_bytes = sk_pke_bytes + cfg["matrix_seed_bits"] // 8
    ct_bytes = n * (k * d_u + d_v) // 8
    sk_kem_bytes = sk_pke_bytes + pk_bytes + (cfg["public_key_hash_bits"] + cfg["rejection_seed_bits"]) // 8
    return {"public_key_bytes": pk_bytes, "ciphertext_bytes": ct_bytes,
            "decapsulation_key_bytes": sk_kem_bytes, "shared_key_bytes": cfg["key_bits"] // 8}
