# This test computes the sign of (z - theta) using a FSS sign gate in a 2PC setting.
import funshade
import numpy as np

#%%
#==============================================================================#
#                              PARAMETER SELECTION                             #
#==============================================================================#
K = 1000        # Number of elements in the input vector
theta = 1234    # Threshold to compare it with

#%%
#==============================================================================#
#                             EXPERIMENT PREPARATION                           #
#==============================================================================#
# Create integer vector of length K
rng = np.random.default_rng(seed=42)
z = rng.integers(-10000, 
                10000, size=K, dtype=funshade.DTYPE)

# Create parties
class party:
    def __init__(self, j: int):
        self.j = j
P0 = party(0)
P1 = party(1)

#%%
#==============================================================================#
#                                 OFFLINE PHASE                                #
#==============================================================================#
# (1) Generate input masks and fss keys (Semi-Honest third party, TEE, 2PC interaction)
r_in0, r_in1, k0, k1 = funshade.FssGenSign(K, theta)
# Distribute randomness to (P0, P1)
P0.r_in_j = r_in0;           P1.r_in_j = r_in1
P0.k_j    = k0;              P1.k_j    = k1

# (2) Generate secret shares of the input vector (z)
z_0 = rng.integers(np.iinfo(funshade.DTYPE).min,
                   np.iinfo(funshade.DTYPE).max, size=K, dtype=funshade.DTYPE)
z_1 = z - z_0
# Distribute shares to (P0, P1)
P0.z_j = z_0;                P1.z_j = z_1


#%%
#==============================================================================#
#                                  ONLINE PHASE                                #
#==============================================================================#
# (3) Mask the input vector (z) with the input masks (r_in)
P0.z_hat_j = P0.z_j + P0.r_in_j
P1.z_hat_j = P1.z_j + P1.r_in_j

# (4) Compute the comparison to the threshold theta
P0.o_j = funshade.FssEvalSign(K, P0.j, P0.k_j, P0.z_hat_j)
P1.o_j = funshade.FssEvalSign(K, P1.j, P1.k_j, P1.z_hat_j)

# (5) Reconstruct the final result
o = P0.o_j + P1.o_j

#%%
#==============================================================================#
#                              CHECK CORRECTNESS                               #
#==============================================================================#
# Check the final result
o_ground = (z > theta)                         # Ground truth
assert np.allclose(o_ground, o)
print("FSS gate executed correctly")
# %%
