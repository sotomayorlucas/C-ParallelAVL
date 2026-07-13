#!/usr/bin/env julia

using POMDPs
using POMDPTools
using JSON3
using Random
using LinearAlgebra
using Statistics
using Pkg
using SHA

const ACTIONS = (:wait, :intervene)
const OBS = (:x, :y)
const STATES = 1:4
const RNG_SEED = 20260713

# -----------------------------------------------------------------------------
# Exact positive instance: four concrete states, two predictive classes.
# -----------------------------------------------------------------------------

struct LumpablePOMDP <: POMDP{Int, Symbol, Symbol} end

const LUMP_T = Dict(
    :wait => [
        0.55 0.20 0.20 0.05;
        0.20 0.55 0.05 0.20;
        0.15 0.05 0.55 0.25;
        0.05 0.15 0.25 0.55
    ],
    :intervene => [
        0.65 0.25 0.08 0.02;
        0.25 0.65 0.02 0.08;
        0.45 0.20 0.25 0.10;
        0.20 0.45 0.10 0.25
    ]
)
const LUMP_OX = Dict(
    :wait => [0.85, 0.85, 0.25, 0.25],
    :intervene => [0.70, 0.70, 0.40, 0.40]
)
const LUMP_R = Dict(
    :wait => [0.8, 0.8, 0.1, 0.1],
    :intervene => [0.35, 0.35, 0.65, 0.65]
)
const LUMP_INIT = [0.10, 0.20, 0.30, 0.40]

POMDPs.states(::LumpablePOMDP) = collect(STATES)
POMDPs.actions(::LumpablePOMDP) = collect(ACTIONS)
POMDPs.observations(::LumpablePOMDP) = collect(OBS)
POMDPs.stateindex(::LumpablePOMDP, s::Int) = s
POMDPs.actionindex(::LumpablePOMDP, a::Symbol) = a === :wait ? 1 : 2
POMDPs.obsindex(::LumpablePOMDP, o::Symbol) = o === :x ? 1 : 2
POMDPs.discount(::LumpablePOMDP) = 0.95
POMDPs.initialstate(::LumpablePOMDP) = SparseCat(collect(STATES), copy(LUMP_INIT))
POMDPs.isterminal(::LumpablePOMDP, ::Int) = false

function POMDPs.transition(::LumpablePOMDP, s::Int, a::Symbol)
    return SparseCat(collect(STATES), vec(copy(LUMP_T[a][s, :])))
end

function POMDPs.observation(::LumpablePOMDP, a::Symbol, sp::Int)
    px = LUMP_OX[a][sp]
    return SparseCat(collect(OBS), [px, 1.0-px])
end

POMDPs.reward(::LumpablePOMDP, s::Int, a::Symbol) = LUMP_R[a][s]

struct QuotientBelief
    pA::Float64
end

struct QuotientUpdater <: Updater
    pomdp::LumpablePOMDP
end

function POMDPs.initialize_belief(::QuotientUpdater, dist)
    pA = sum(pdf(dist, s) for s in 1:2)
    return QuotientBelief(pA)
end

class_transition(a::Symbol) = a === :wait ? (0.75, 0.20) : (0.90, 0.65)
class_obs_x(a::Symbol) = a === :wait ? (0.85, 0.25) : (0.70, 0.40)

function POMDPs.update(::QuotientUpdater, b::QuotientBelief, a::Symbol, o::Symbol)
    paa, pba = class_transition(a)
    predA = b.pA*paa + (1.0-b.pA)*pba
    oxA, oxB = class_obs_x(a)
    lA = o === :x ? oxA : 1.0-oxA
    lB = o === :x ? oxB : 1.0-oxB
    z = predA*lA + (1.0-predA)*lB
    z > 0.0 || error("zero quotient observation likelihood")
    return QuotientBelief(predA*lA/z)
end

function full_obs_x(m, b::DiscreteBelief, a::Symbol)
    total = 0.0
    for s in STATES
        for sp in STATES
            total += b.b[s] * LUMP_T[a][s, sp] * LUMP_OX[a][sp]
        end
    end
    return total
end

function quotient_obs_x(b::QuotientBelief, a::Symbol)
    paa, pba = class_transition(a)
    predA = b.pA*paa + (1.0-b.pA)*pba
    oxA, oxB = class_obs_x(a)
    return predA*oxA + (1.0-predA)*oxB
end

full_reward(b::DiscreteBelief, a::Symbol) = sum(b.b[s]*LUMP_R[a][s] for s in STATES)
quotient_reward(b::QuotientBelief, a::Symbol) = b.pA*LUMP_R[a][1] + (1.0-b.pA)*LUMP_R[a][3]

greedy_full(b::DiscreteBelief) = full_reward(b, :wait) >= full_reward(b, :intervene) ? :wait : :intervene
greedy_quotient(b::QuotientBelief) = quotient_reward(b, :wait) >= quotient_reward(b, :intervene) ? :wait : :intervene

function sample_categorical(rng::AbstractRNG, probs::AbstractVector{<:Real})
    u = rand(rng)
    c = 0.0
    for (i, p) in enumerate(probs)
        c += p
        if u <= c + 1e-15
            return i
        end
    end
    return length(probs)
end

function sequence_probability(T::Dict, OX::Dict, s0::Int, seq)
    mass = zeros(Float64, 4)
    mass[s0] = 1.0
    for (a, o) in seq
        next = zeros(Float64, 4)
        for s in STATES, sp in STATES
            po = o === :x ? OX[a][sp] : 1.0-OX[a][sp]
            next[sp] += mass[s]*T[a][s,sp]*po
        end
        mass = next
    end
    return sum(mass)
end

function affine_rank(rows::Matrix{Float64}; atol=1e-10)
    d = rows[1:end-1, :] .- rows[end, :]'
    return rank(d; atol=atol)
end

function run_exact_quotient()
    m = LumpablePOMDP()
    full_up = DiscreteUpdater(m)
    q_up = QuotientUpdater(m)
    bfull = initialize_belief(full_up, initialstate(m))
    bq = initialize_belief(q_up, initialstate(m))

    rng = MersenneTwister(RNG_SEED)
    max_mass_error = 0.0
    max_obs_error = 0.0
    max_reward_error = 0.0
    action_disagreements = 0
    updates = 0

    for _ in 1:5000
        bfull = initialize_belief(full_up, initialstate(m))
        bq = initialize_belief(q_up, initialstate(m))
        for _ in 1:20
            a = rand(rng, collect(ACTIONS))
            px_full = full_obs_x(m, bfull, a)
            px_q = quotient_obs_x(bq, a)
            max_obs_error = max(max_obs_error, abs(px_full-px_q))
            for aa in ACTIONS
                max_reward_error = max(max_reward_error, abs(full_reward(bfull, aa)-quotient_reward(bq, aa)))
            end
            action_disagreements += greedy_full(bfull) != greedy_quotient(bq)
            o = rand(rng) < px_full ? :x : :y
            bfull = update(full_up, bfull, a, o)
            bq = update(q_up, bq, a, o)
            max_mass_error = max(max_mass_error, abs(sum(bfull.b[1:2])-bq.pA))
            updates += 1
        end
    end

    # Closed-loop simulation using the same greedy policy from both beliefs.
    rng_sim = MersenneTwister(RNG_SEED + 1)
    episodes = 2000
    horizon = 50
    returns = Float64[]
    simulation_disagreements = 0
    max_sim_mass_error = 0.0
    for _ in 1:episodes
        s = sample_categorical(rng_sim, LUMP_INIT)
        bf = initialize_belief(full_up, initialstate(m))
        bqc = initialize_belief(q_up, initialstate(m))
        ret = 0.0
        disc = 1.0
        for _ in 1:horizon
            af = greedy_full(bf)
            aq = greedy_quotient(bqc)
            simulation_disagreements += af != aq
            a = af
            ret += disc*reward(m, s, a)
            sp = sample_categorical(rng_sim, vec(LUMP_T[a][s,:]))
            px = LUMP_OX[a][sp]
            o = rand(rng_sim) < px ? :x : :y
            bf = update(full_up, bf, a, o)
            bqc = update(q_up, bqc, a, o)
            max_sim_mass_error = max(max_sim_mass_error, abs(sum(bf.b[1:2])-bqc.pA))
            s = sp
            disc *= discount(m)
        end
        push!(returns, ret)
    end

    # Warmed timing over one fixed, everywhere-possible trace.
    seq = [(ACTIONS[1 + (i % 2)], OBS[1 + ((i ÷ 3) % 2)]) for i in 1:20000]
    function time_full()
        b = initialize_belief(full_up, initialstate(m))
        @elapsed for (a,o) in seq
            b = update(full_up, b, a, o)
        end
    end
    function time_q()
        b = initialize_belief(q_up, initialstate(m))
        @elapsed for (a,o) in seq
            b = update(q_up, b, a, o)
        end
    end
    time_full(); time_q()
    full_times = [time_full() for _ in 1:5]
    q_times = [time_q() for _ in 1:5]

    tests = [
        [(:wait,:x)],
        [(:intervene,:x)],
        [(:wait,:x),(:wait,:x)],
        [(:intervene,:x),(:wait,:x)]
    ]
    rows = [sequence_probability(LUMP_T, LUMP_OX, s, seqi) for s in STATES, seqi in tests]

    return Dict(
        "pompd_model" => "LumpablePOMDP",
        "full_states" => 4,
        "full_simplex_dimension" => 3,
        "compressed_coordinates" => 1,
        "predictive_affine_rank" => affine_rank(rows),
        "random_trace_updates" => updates,
        "max_class_mass_error" => max_mass_error,
        "max_observation_prediction_error" => max_obs_error,
        "max_expected_reward_error" => max_reward_error,
        "greedy_action_disagreements" => action_disagreements,
        "simulation_episodes" => episodes,
        "simulation_horizon" => horizon,
        "simulation_action_disagreements" => simulation_disagreements,
        "simulation_max_class_mass_error" => max_sim_mass_error,
        "mean_discounted_return" => mean(returns),
        "return_standard_error" => std(returns)/sqrt(length(returns)),
        "logical_payload_bytes_full" => 4*sizeof(Float64),
        "logical_payload_bytes_compressed" => sizeof(Float64),
        "julia_summarysize_full_belief" => Base.summarysize(bfull),
        "julia_summarysize_compressed_belief" => Base.summarysize(bq),
        "full_update_seconds_median_20000" => median(full_times),
        "compressed_update_seconds_median_20000" => median(q_times),
        "timing_ratio_full_over_compressed" => median(full_times)/median(q_times),
        "test_matrix" => rows
    )
end

# -----------------------------------------------------------------------------
# Negative instance: predictive rank three and a two-moment non-closure witness.
# -----------------------------------------------------------------------------

struct GenericPOMDP <: POMDP{Int, Symbol, Symbol} end

const GEN_QX = Dict(
    :a => [0.1, 0.3, 0.6, 0.9],
    :b => [0.2, 0.8, 0.4, 0.7]
)
const GEN_R = Dict(
    :a => [0.0, 1.0, 0.0, 1.0],
    :b => [1.0, 0.0, 1.0, 0.0]
)

POMDPs.states(::GenericPOMDP) = collect(STATES)
POMDPs.actions(::GenericPOMDP) = [:a, :b]
POMDPs.observations(::GenericPOMDP) = collect(OBS)
POMDPs.stateindex(::GenericPOMDP, s::Int) = s
POMDPs.actionindex(::GenericPOMDP, a::Symbol) = a === :a ? 1 : 2
POMDPs.obsindex(::GenericPOMDP, o::Symbol) = o === :x ? 1 : 2
POMDPs.discount(::GenericPOMDP) = 0.95
POMDPs.initialstate(::GenericPOMDP) = SparseCat(collect(STATES), fill(0.25, 4))
POMDPs.isterminal(::GenericPOMDP, ::Int) = false
POMDPs.transition(::GenericPOMDP, s::Int, ::Symbol) = SparseCat([s], [1.0])
function POMDPs.observation(::GenericPOMDP, a::Symbol, sp::Int)
    px = GEN_QX[a][sp]
    return SparseCat(collect(OBS), [px, 1.0-px])
end
POMDPs.reward(::GenericPOMDP, s::Int, a::Symbol) = GEN_R[a][s]

moment_features(b::AbstractVector) = begin
    xs = [0.0, 1.0, 2.0, 3.0]
    (sum(b .* xs), sum(b .* (xs.^2)))
end

generic_obs_x(b::AbstractVector, a::Symbol) = dot(b, GEN_QX[a])
generic_reward(b::AbstractVector, a::Symbol) = dot(b, GEN_R[a])
generic_greedy(b::AbstractVector) = generic_reward(b,:a) >= generic_reward(b,:b) ? :a : :b

function random_belief(rng)
    v = randexp(rng, 4)
    return v/sum(v)
end

function run_nonclosure()
    m = GenericPOMDP()
    up = DiscreteUpdater(m)
    bplus = [5/24, 3/8, 1/8, 7/24]
    bminus = [7/24, 1/8, 3/8, 5/24]
    bp = DiscreteBelief(m, Float64.(bplus))
    bm = DiscreteBelief(m, Float64.(bminus))

    mp = moment_features(bp.b)
    mm = moment_features(bm.b)
    obs_a_diff = abs(generic_obs_x(bp.b,:a)-generic_obs_x(bm.b,:a))
    obs_b_diff = abs(generic_obs_x(bp.b,:b)-generic_obs_x(bm.b,:b))
    pair_tv_b = obs_b_diff # binary Bernoulli TV
    deficiency_lb = pair_tv_b/2
    reward_gap_plus = generic_reward(bp.b,:a)-generic_reward(bp.b,:b)
    reward_gap_minus = generic_reward(bm.b,:b)-generic_reward(bm.b,:a)

    # Show that the external Bayesian updater sends the two same-moment beliefs
    # to different compressed coordinates after the same action and observation.
    bp_post = update(up, bp, :b, :x)
    bm_post = update(up, bm, :b, :x)
    post_mp = moment_features(bp_post.b)
    post_mm = moment_features(bm_post.b)

    tests = [
        [(:a,:x)],
        [(:b,:x)],
        [(:a,:x),(:a,:x)]
    ]
    function gen_sequence_prob(s0, seq)
        p = 1.0
        for (a,o) in seq
            px = GEN_QX[a][s0]
            p *= o === :x ? px : 1.0-px
        end
        p
    end
    rows = [gen_sequence_prob(s, seqi) for s in STATES, seqi in tests]

    # A declared approximate realization: least-squares decoder from two moments.
    rng = MersenneTwister(RNG_SEED + 2)
    ntrain = 30000
    X = zeros(ntrain, 3)
    Y = zeros(ntrain, 4)
    for i in 1:ntrain
        b = random_belief(rng)
        m1,m2 = moment_features(b)
        X[i,:] .= (1.0,m1,m2)
        Y[i,:] .= b
    end
    coef = X \ Y
    ntest = 10000
    pred_errors = Float64[]
    regrets = Float64[]
    belief_tvs = Float64[]
    for _ in 1:ntest
        b = random_belief(rng)
        m1,m2 = moment_features(b)
        bh = vec([1.0,m1,m2]'*coef)
        bh = max.(bh, 0.0)
        bh = sum(bh) > 0 ? bh/sum(bh) : fill(0.25,4)
        push!(belief_tvs, 0.5*sum(abs.(b-bh)))
        push!(pred_errors, maximum(abs(generic_obs_x(b,a)-generic_obs_x(bh,a)) for a in (:a,:b)))
        ah = generic_greedy(bh)
        optimum = maximum(generic_reward(b,a) for a in (:a,:b))
        push!(regrets, optimum-generic_reward(b,ah))
    end

    return Dict(
        "pomdp_model" => "GenericPOMDP",
        "predictive_tests" => [[String(a)*":"*String(o) for (a,o) in seq] for seq in tests],
        "predictive_test_matrix" => rows,
        "predictive_affine_rank" => affine_rank(rows),
        "candidate_compression" => "first two ordinary moments",
        "candidate_coordinates" => 2,
        "belief_plus" => bplus,
        "belief_minus" => bminus,
        "moments_plus" => collect(mp),
        "moments_minus" => collect(mm),
        "same_moments_error" => maximum(abs.([mp[1]-mm[1], mp[2]-mm[2]])),
        "observation_x_difference_action_a" => obs_a_diff,
        "observation_x_difference_action_b" => obs_b_diff,
        "pairwise_tv_action_b" => pair_tv_b,
        "deficiency_lower_bound_same_code" => deficiency_lb,
        "optimal_action_plus" => String(generic_greedy(bp.b)),
        "optimal_action_minus" => String(generic_greedy(bm.b)),
        "reward_gap_plus" => reward_gap_plus,
        "reward_gap_minus" => reward_gap_minus,
        "deterministic_policy_worst_case_regret_lower_bound" => min(reward_gap_plus,reward_gap_minus),
        "randomized_policy_minimax_regret_lower_bound" => min(reward_gap_plus,reward_gap_minus)/2,
        "post_update_moments_plus" => collect(post_mp),
        "post_update_moments_minus" => collect(post_mm),
        "post_update_moment_separation" => maximum(abs.([post_mp[1]-post_mm[1],post_mp[2]-post_mm[2]])),
        "approximation_training_beliefs" => ntrain,
        "approximation_test_beliefs" => ntest,
        "approx_mean_belief_tv" => mean(belief_tvs),
        "approx_max_belief_tv" => maximum(belief_tvs),
        "approx_mean_prediction_error" => mean(pred_errors),
        "approx_max_prediction_error" => maximum(pred_errors),
        "approx_mean_greedy_regret" => mean(regrets),
        "approx_max_greedy_regret" => maximum(regrets)
    )
end

function package_versions()
    versions = Dict{String,String}()
    for (_,info) in Pkg.dependencies()
        if info.name in ("POMDPs","POMDPTools","JSON3")
            versions[info.name] = string(info.version)
        end
    end
    versions["Julia"] = string(VERSION)
    return versions
end

function main()
    exact = run_exact_quotient()
    negative = run_nonclosure()
    checks = Dict(
        "exact_rank_one" => exact["predictive_affine_rank"] == 1,
        "exact_updates_match" => exact["max_class_mass_error"] < 1e-12,
        "exact_predictions_match" => exact["max_observation_prediction_error"] < 1e-12,
        "exact_rewards_match" => exact["max_expected_reward_error"] < 1e-12,
        "exact_policy_match" => exact["greedy_action_disagreements"] == 0 && exact["simulation_action_disagreements"] == 0,
        "generic_rank_three" => negative["predictive_affine_rank"] == 3,
        "moments_collide" => negative["same_moments_error"] < 1e-12,
        "collision_changes_prediction" => negative["pairwise_tv_action_b"] > 0.1,
        "collision_changes_decision" => negative["optimal_action_plus"] != negative["optimal_action_minus"],
        "external_updater_breaks_moment_closure" => negative["post_update_moment_separation"] > 1e-3
    )
    result = Dict(
        "schema" => "sot-v5-pomdps-1.0",
        "seed" => RNG_SEED,
        "versions" => package_versions(),
        "exact_predictive_quotient" => exact,
        "nonclosure_certificate" => negative,
        "checks" => checks,
        "all_pass" => all(values(checks)),
        "evidence_level" => "internal integration with independently maintained POMDPs.jl; not external R2"
    )
    canonical = JSON3.write(result)
    result["canonical_sha256_without_digest"] = bytes2hex(sha256(canonical))
    outdir = get(ENV, "SOT_V5_OUT", joinpath(@__DIR__, "out"))
    mkpath(outdir)
    open(joinpath(outdir,"pomdps_results.json"),"w") do io
        JSON3.pretty(io, result)
        write(io,"\n")
    end
    println(JSON3.pretty(result))
    result["all_pass"] || error("V5 POMDPs validation failed")
end

main()
