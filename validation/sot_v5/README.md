# SOT V5 - POMDPs.jl belief-compression validation

This branch is an isolated CI carrier. It is not intended to merge into the unrelated concurrent-AVL project.

The validation uses Julia 1.12.6, POMDPs.jl 1.0.x, and POMDPTools 1.1.x. It checks two cases:

1. A four-state POMDP with an exact one-coordinate predictive quotient. The quotient updater is compared against `POMDPTools.DiscreteUpdater` over 100,000 randomized updates and 2,000 closed-loop episodes.
2. A generic four-state POMDP with predictive affine rank three. Two beliefs have identical first two moments but different future observation laws and opposite optimal actions, certifying non-closure of the proposed two-moment compression.

A separate standard-library Python checker recomputes the rational rank, deficiency, and regret witnesses without importing Julia or the POMDP implementation.

This is an internal external-system integration. It is not an external R2 reproduction of the SOT 1.0 blind challenge.
