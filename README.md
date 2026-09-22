# Kyber QROM security estimator

Classical and quantum lattice attack costs, decryption-failure probabilities, key/ciphertext sizes, and conditional QROM security estimation for generalized Kyber suites. The calculations use the  lattice-estimator and the QROM reduction introduced in Kyber Kem report.

## Running commands

SageMath with NumPy, SciPy and lattice estimator (https://github.com/malb/lattice-estimator) must be installed. Run from this directory:

```bash
bash run.sh
```

Or select Sage directly:

```bash
sage -python Kyber.py
# Alternatively, specify the Sage Python executable:
SAGE_PYTHON=/path/to/sage-python bash run.sh
```


## Results

All suites use `n=512`, `q=7681`, and lossless 13-bit public-key encoding. Here `m` is module rank, `eta=ks=ke=ke_ct` is the centered-binomial parameter, and `du,dv` are ciphertext compression widths.

| Target | m | eta | du | dv |
|---:|---:|---:|---:|---:|
| 128 | 2 | 3 | 11 | 4 |
| 192 | 3 | 2 | 11 | 4 |
| 256 | 4 | 2 | 12 | 5 |

Previously computed results for these parameters:

| Target | Classical bits | Quantum bits | Model failure bound | Conditional QROM bits |
|---:|---:|---:|---:|---:|
| 128 | 231.71 | 206.65 | 2^-288.385 | 139.24 |
| 192 | 348.42 | 309.99 | 2^-380.205 | 242.18 |
| 256 | 482.09 | 428.74 | 2^-445.408 | 309.41 |

| Target | Public key (bytes) | Ciphertext (bytes) | Decapsulation key (bytes) | Shared key (bytes) |
|---:|---:|---:|---:|---:|
| 128 | 1728 | 1664 | 3520 | 64 |
| 192 | 2560 | 2368 | 5184 | 64 |
| 256 | 3392 | 3392 | 6848 | 64 |

The QROM calculation uses query count and depth `2^64`, a 512-bit message space, assumed PRF advantage `2^-320`, and zero additional runtime-loss bits. `PASS` requires the target score and a two-bit reserve on each of the four advantage contributions.

In the returned `qrom` dictionary, `b_qrom` is the conditional score and
`lg_adv` contains the log2 advantage contributions. `b_lat_adj` and `b_df_adj`
include reduction losses; `b_lat_req`, `b_df_req`, `b_prf_req`, and `b_msg_req`
give required bit exponents or lengths with the reserve. `target_ok` checks
the score against `b_tgt`; `reserve_ok` checks all four term budgets.

## Estimator options

The lattice options are set in [MLWE_security.py](MLWE_security.py):

| Option | Default | Meaning |
|---|---|---|
| `red_cost_model` | `RC.ADPS16` / `RC.ChaLoy21` | Classical / quantum lattice-reduction costs. |
| `red_shape_model` | `"gsa"` | Geometric Series Assumption for reduced basis shapes in primal attacks. |
| `full` | `True` | Evaluate all eight configured attacks; `False` selects a smaller subset. |
| `deny_list` | `("bkw",)` in full mode | Remove the default BKW routine before replacement. |
| `add_list` | `(("bkw", bkw_checked),)` in full mode | Use the BKW wrapper with the conservative infinite-sample fallback. |
| `jobs` | `8` | Worker processes evaluating separate attacks concurrently. |
| `catch_exceptions` | `False` | Propagate estimation errors. |
| `quiet` | `True` | Suppress the estimator's normal attack summaries. |
| `max_beta` | `4096` | Upper search limit for the lattice-reduction block size. |


The suite runner also supports these function arguments:

| Option | Default | Meaning |
|---|---|---|
| `precision` | `768` | working precision in bits for failure estimation. |
| `failure_only` | `False` | Compute failure probability and sizes without lattice estimates. |
| `search_compression` | `False` | Search compression settings in ciphertext-size order. |
| `sensitivity` | `False` | Print conditional scores for several query/depth budgets. |

