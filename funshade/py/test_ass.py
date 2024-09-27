# This test replaces the Π-Secret Sharing with the additive secret sharing
import funshade
import numpy as np

#%%
#==============================================================================#
#                              PARAMETER SELECTION                             #
#==============================================================================#
K = 1000        # Number of vectors in the database
l = 512         # Length (number of elements) of each vector (2**8)
theta = 0.4     # Threshold for the matching
max_el = 2**12  # Maximum value for vector elements. To avoid overflows:
                #       2*log2(max_el) + log2(l) <= 32 bits

#%%
#==============================================================================#
#                             EXPERIMENT PREPARATION                           #
#==============================================================================#
# Create normalized reference templates (Y) and live template (x)
rng = np.random.default_rng(seed=42)
def sample_biometric_template(K: int, l: int):
    """Sample a set of K biometric templates of length l."""
    templates = rng.uniform(-1, 1, size=(K,l))
    return templates / np.linalg.norm(templates, axis=1, keepdims=True)
x_float = sample_biometric_template(1, l).flatten()
Y_float = sample_biometric_template(K, l)

# Convert to integers via fixed-point scaling (multiply by a scaling factor max_el)
x = (x_float*max_el).astype(funshade.DTYPE)
Y = (Y_float*max_el).astype(funshade.DTYPE)
theta_fp = int(theta*(max_el**2))          # threshold must be upscaled twice

# Alternatively, you could directly input integer templates:
# x = np.random.randint(-max_el, max_el, size=l,     dtype=funshade.DTYPE)
# Y = np.random.randint(-max_el, max_el, size=(K,l), dtype=funshade.DTYPE)

# Create parties
class party:
    def __init__(self, j: int):
        self.j = j
BP   = party(0) # P0
Gate = party(1) # P1

#%%
#==============================================================================#
#                                 OFFLINE PHASE                                #
#==============================================================================#
# (1) Generate correlated randomness (Semi-Honest third party, TEE, 2PC interaction)
a0, a1, b0, b1, c0, c1, r_in0, r_in1, k0, k1 = funshade.setup_ss(K, l, theta_fp)

# Distribute randomness to (P0, P1)
BP.a_j    = a0;            Gate.a_j    = a1
BP.b_j    = b0;            Gate.b_j    = b1
BP.c_j    = c0;            Gate.c_j    = c1
BP.r_in_j = r_in0;         Gate.r_in_j = r_in1
BP.k_j    = k0;            Gate.k_j    = k1

# (2) Get and secret share the reference DB (Y)
BP.Y     =  Y.flatten()                           # Biometric Provider (BP) receives reference DB (enrollment)
BP.d_y   =  funshade.share_ss(K, l, BP.Y, BP.a_j) # BP generates d share of Y
BP.e_y   =  funshade.share_ss(K, l, BP.Y, BP.b_j) # BP generates e share of Y
Gate.d_y = BP.d_y;       Gate.e_y = BP.e_y        # BP: Send(BP.d_y, BP.e_y) --> Gate
del BP.Y                                          # Delete the plaintext reference DB

#%%
#==============================================================================#
#                                  ONLINE PHASE                                #
#==============================================================================#
# (3) Get and secret share the live template
Gate.x   =  np.tile(x, K)                              # Gate captures the live template (x)
Gate.d_x =  funshade.share_ss(K, l, Gate.x, Gate.a_j)  # Gate generates d share of x
Gate.e_x =  funshade.share_ss(K, l, Gate.x, Gate.b_j)  # Gate generates e share of x
BP.d_x   = Gate.d_x;       BP.e_x = Gate.e_x           # Gate: Send(Gate.d_x, Gate.e_x) --> BP
del Gate.x                                             # Delete the plaintext live template

# (4) Compute the masked matching score (z_hat) shares
BP.z_hat_j   = funshade.eval_dist_ss(K, l, BP.j,
        BP.r_in_j,   BP.d_y,    BP.e_y,     BP.a_j,   BP.b_j,   BP.c_j)
Gate.z_hat_j = funshade.eval_dist_ss(K, l, Gate.j,
        Gate.r_in_j,   Gate.d_x,    Gate.e_x,     Gate.a_j,   Gate.b_j,   Gate.c_j)

# Exchange z_hat_j shares to reconstruct z_hat
BP.z_hat_nj   = Gate.z_hat_j                 # BP: Send(z_hat_j) --> Gate
Gate.z_hat_nj = BP.z_hat_j                   # Gate: Send(z_hat_j) --> BP
# Compute the comparison to the threshold theta
BP.o_j     = funshade.eval_sign(K, BP.j, BP.k_j, BP.z_hat_j, BP.z_hat_nj)
Gate.o_j   = funshade.eval_sign(K, Gate.j, Gate.k_j, Gate.z_hat_j, Gate.z_hat_nj)

# (5) Reconstruct the final result
o = BP.o_j + Gate.o_j

#%%
#==============================================================================#
#                              CHECK CORRECTNESS                               #
#==============================================================================#
# Check the matching score (z) for the live template (x) and the reference DB (Y)
z_ground = x@Y.T                                               # Ground truth
z_exper  = (BP.z_hat_j+Gate.z_hat_j) - (BP.r_in_j+Gate.r_in_j) # Experimental result
assert np.allclose(z_ground, z_exper)

# Check the final result
o_ground = (x_float@Y_float.T > theta)                         # Ground truth
assert np.allclose(o_ground, o)
print("Funshade executed correctly")