# SOT V4 external-system validation

This isolated branch integrates Sufficient Observer Theory 1.0 with two independently maintained systems:

1. `py-tgb==2.2.0` on the official `tgbl-uci` temporal graph stream and official negative samples.
2. `differential-dataflow==0.24.0` / `timely==0.30` on the TGB edge stream.

The branch is a temporary CI carrier and is not intended to merge into `concurrent-avl`.

The acceptance gate requires:

- real-derived directed-WL blindness certificates with temporal closure `2` versus `0`;
- a six-coordinate fibre whose Walsh-minimal repair has rank one;
- exact Python incremental maintenance at checkpoints;
- exact Differential Dataflow maintenance under insertions and window expirations;
- a canonical degree-blind `C6` versus `2C3` pair;
- link-prediction evaluation using TGB's official negative samples.

This is an internal external-system integration, not an independent R2 reproduction.
