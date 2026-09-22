from sage.all import log, oo
from estimator import LWE, ND, RC
from estimator import conf, lwe_primal, lwe_dual
from estimator.reduction import ADPS16, MATZOV


conf.max_beta = lwe_primal.max_beta_global = lwe_dual.max_beta_global = 4096

MODELS = {
    "classical": RC.ADPS16,
    "quantum": RC.ChaLoy21,
    "quantum_adps16": ADPS16(mode="quantum"),
    "quantum_matzov": MATZOV(nn="quantum"),
    "paranoid": ADPS16(mode="paranoid"),
}

ATTACKS = {"arora-gb", "bkw", "usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "dual", "dual_hybrid"}


def bkw_checked(params):
    try:
        return LWE.coded_bkw(params)
    except ValueError as error:
        if "ceil() on infinity" not in str(error):
            raise
        # Upstream sample amplification can run into an infinite sample count
        # on these large dimensions. Also evaluate the strictly easier model
        # with unlimited original samples, without amplifying their noise.
        cost = LWE.coded_bkw(params.updated(m=oo))
        if cost["rop"] == oo:
            raise ArithmeticError("BKW remains unresolved with unlimited samples") from error
        cost["sample_model"] = "unlimited original samples (conservative relaxation)"
        return cost


def estimate(ps, model="quantum", full=True):
    if not ps.ks == ps.ke == ps.ke_ct:
        raise ValueError("This suite adapter requires symmetric noise; asymmetric hybrids need separate estimates")
    n, k, eta1, eta2, q = ps.n, ps.m, ps.ks, ps.ke_ct, ps.q
    # For eta1=eta2 the pk has kn samples, ciphertext (k+1)n. Giving both
    # distinguishers the larger sample budget is conservative. 
    params = LWE.Parameters(n=n*k, m=n*(k+1), q=q,
                            Xs=ND.CenteredBinomial(eta1),
                            Xe=ND.CenteredBinomial(eta2))
    deny = ("bkw",) if full else ("arora-gb", "bkw", "bdd_hybrid", "bdd_mitm_hybrid")
    add = (("bkw", bkw_checked),) if full else ()
    costs = LWE.estimate(params, red_cost_model=MODELS[model], red_shape_model="gsa",
                         deny_list=deny, add_list=add, jobs=8, catch_exceptions=False, quiet=True)
    rows = {}
    for attack, cost in costs.items():
        bits = float(log(cost["rop"], 2)) if cost["rop"] != oo else None
        rows[attack] = {
            "bits": bits,
            "cost": {str(key): str(value) for key, value in cost.items() if key != "problem"},
        }
    finite = {a: r["bits"] for a, r in rows.items() if r["bits"] is not None}
    
    return {"n": n, "k": k, "eta1": eta1, "eta2": eta2, "q": q,
            "lwe_dimension": n*k, "samples": n*(k+1), "model": model,
            "full": full, "max_beta": conf.max_beta,
            "minimum_bits": min(finite.values()), "best_attack": min(finite, key=finite.get),
            "attacks": rows}
