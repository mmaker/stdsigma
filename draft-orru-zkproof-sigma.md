---
title: "Sigma Protocols"
category: info

docname: draft-orru-zkproof-sigma-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - zero-knowledge
venue:
#  group: WG
#  type: Working Group
#  mail: WG@examplecom
#  arch: https://examplecom/WG
  github: "mmaker/stdsigma"
  latest: "https://mmaker.github.io/stdsigma/draft-orru-zkproof-sigma.html"

author:
 -
    fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"
 -
    fullname: "Stephan Krenn"
    organization: AIT
    email: stephan.krenn@ait.ac.at

normative:

informative:

--- abstract

This document describes Sigma protocols, a secure, general-purpose non-interactive zero-knowledge proof of knowledge. Concretely, the scheme allows proving knowledge of a witness, without revealing any information about the undisclosed messages or the signature itself, while at the same time, guarantying soundness of the overall protocols.

--- middle

# Introduction

Zero-knowledge proofs of knowledge allow a prover to convince a verifier that they know a secret piece of information, without revealing anything except that the claim itself already reveals.
Sigma protocols, introduced by Schnorr in 1991, they play an essential component in the building of a number of cryptographic constructions, such as anonymous credentials, password-authenticated
key exchange, signatures, ring signatures, blind signatures, multi-signatures, threshold signatures and
more. This spec provides guidelines for correctly implementing Sigma protocols.

## Terminology

R[name]
: the _relation_, potentially associated a to a `name` for disambiguation: the set of valid instances and witnesses for the proof system.

Y
: the _instance_: the public information shared between the prover and the verifier.

w
: the _witness_. The secret information solely known by the prover. Note there may be
multiple witnesses for a given `Y`.

proof
: The zero-knowledge proof output.

In a zero-knowledge proof, the _witness_ is secret information, while
the _statement_ is public. A _proof_ is a sequence of bytes
attesting that a witness is in some relation with the statement.

Proofs described in this spec are zero-knowledge and sound. Zero
knowledge means that the protocol does not leak any information about
the prover's witness beyond what the attacker may infer from the proven
statement or from other sources [@zkproof-reference 1.6.4]. Soundness
means that it is not possible to make the verifier accept for statements
for which no valid witness exists [@zkproof-reference 1.6.2].

In particular, we will focus on non-malleable extractable proofs, that
is, proofs where the witness does not only exist but is also
precisely known by the prover. These protocols are also known as proofs
of knowledge [@STOC:GolMicRac85; @STOC:FeiFiaSha87; @C:BelGol92] and are
said to satisfy _knowledge soundness_ [@damgard04]. Non-malleability
means that, in addition, the proof is secure against man-in-the middle
attacks, and attackers cannot produce a new valid proof by tampering
another valid proof.

## Notation {#sec:notation}

GG
: A safe elliptic-curve group.

point\_to\_octets\_GG(P) -> ostr
: Return the canonical representation of the point P of the elliptic curve `GG` as an octet string. This operation is also known as serialization. Note that we assume that when the point is valid, all the serialization operations will always succeed to return the octet string representation of the point.

Additional notation will be introduced when describing specific
algebraic objects.

## Document Organization

TODO TODO TODO

## Scope of this document

This document provides guidelines for secure implementations of Sigma protocols and is addressed to applied cryptographers and cryptographic engineers that are looking to implement a generic Sigma protocol as a part of larger protocols.

We consider the problem of having a high-quality entropy source well-suited for cryptographic purposes outside the scope of this document. We will not talk about implementation of cryptographic primitives such as hash functions, or elliptic-curve algebra, but we will provide references for where to find them. Furthermore, we won't provide any guidance for securely storing secrets or producing constant-time code.

# Sigma protocols definition

In the following, we describe a generic interface for Sigma protocols. Such protocols can be used to prove that, for some binary relation `R` and a public value `Y`, a witness `w` such that `(Y, w)` is in `R` is known. Basic statements include proofs of knowledge of a secret key, openings of commitments, and more in general of representations. The type of these elements depends on the specific relation being implemented.

An important property of Sigma protocols is that they are composable: it is possible to prove conjunction and disjunctions of statements in zero-knowledge. Composition of Sigma protocols is dealt separately; for an in-depth discussion of the underlying theory we refer to Cramer [@cramer97].

## Overview

Any Sigma protocol is structured as follows:

- the prover computes a fresh **commitment**, denoted `T`. This element is sometimes also called _nonce_.
- the prover computes, using the so-called Fiat-Shamir transform, a random **challenge**, denoted `c`.
- the prover computes a **response**, denoted `s`, that depends on the commitment and the challenge.

The final proof is constituted of the three-elements above `(T, c, s)`,
and is also referred to as the **transcript**.

## Abstract Sigma Protocols

We define a template class for Sigma protocols denoted `SigmaProtocol`. This is the basic interface that will be implemented remainder of this document. The methods composing
`SigmaProtocol` should be considered _private_ and SHOULD NOT be exposed externally. The public API is described later. Instances are created via the `new` function, which is a class method, while all other functions act on a particular instance. A `SigmaProtocol` consists of the following methods:

- `SigmaProtocol.new(ctx, Y)`, denoting the initialization function. This function takes as input a label identifying local context information `ctx` (such as: session identifiers, to avoid replay attacks; protocol metadata, to avoid hijacking; optionally, a timestamp and some pre-shared randomness, to guarantee freshness of the proof) and a statement `Y`, the public information shared between prover and verifier. This function _should_ pre-compute parts of the statement, or initialize the state of the hash function.

- `(T, pstate) = SigmaProtocol.prover_commit(w)`, denoting the _commitment phase_, that is, the computation of the first message sent by the prover in a Sigma protocol. This method outputs a new commitment together with its associated prover state, depending on the witness known to the prover and the statement to be proven. This step generally requires access to a high-quality entropy source. Leakage of even just of a few bits of the nonce could allow for the complete recovery of the witness [@lattice-attack; @bleichenbacher; @CCS:ANTTY20]. The value `T` is meant to be shared, while `pstate` must be kept secret.

  In particular, we assume that there exists a function `Serialize(T)` that serializes the commitment `T` and that its size is fixed and implicitly determined by the statement `Y`.

- `s = SigmaProtocol.prover_response(pstate, c)`, denoting the _response phase_, that is, the computation of the second message sent by the prover, depending on the witness, the statement, the challenge received from the verifier, and the internal state generated by `prover_commit`. The value `s` is meant to be shared.

- `result = SigmaProtocol.verifier(T, c, s)`, denoting the _verifier algorithm_. This method checks that the _protocol transcript_ is valid for the given statement. The verifier algorithm outputs nothing if verification succeeds, or an error if verification fails.

- `label = SigmaProtocol.label()`, returning a string of 32 bytes uniquely identifying the relation being proven. Implementing this function correctly is vital for security, and it must include all data available in the statement, as well as the parameters and the relation being proven. The label will be used for computing the challenge in the Fiat-Shamir transform. Precise indications on how to implement this function will be given in the following sections.

  If the label is _not_ tied to the relation, then it may be possible to produce another proof for a different relation without knowing its witness. Similarly, if the statement is not tied to the label, then it may be possible to produce proofs for another statement whose witness is related to the original proof.

The final two algorithms describe the _zero-knowledge simulator_. The simulator is primarily an efficient algorithm for proving zero-knowledge in a theoretical construction [@becafi19], but it is also needed for verifying short proofs and for or-composition, where a witness is not known and thus has to be simulated. We have:

- `s <- SigmaProtocol.simulate_response()`, denoting the first stage of the _simulator_. It is an algorithm drawing a random response that follows the same output distribution of the algorithm `prover_response`.

- `T <- SigmaProtocol.simulate_commitment(c, s)`, denoting the second stage of the _simulator_, returning a commitment that follows the same output distribution of the algorithm `prover_commit`.

## The Fiat-Shamir Transform {#sec:fs}

**WARNING**: Interactive Sigma protocols illustrated in this document MUST NOT be used interactively.

The interactive versions of the Sigma protocols presented in this document are not fit for practical applications, due to subtle yet impactful details in their security guarantees. In practice, public-coin protocols such as Sigma protocols can be converted into non-interactive ones through the Fiat and Shamir heuristic [@C:FiaSha86] and subsequent work, e.g., by Bernhard, Pereira and Warinschi [@AC:BerPerWar12].

The underlying idea is to replace the verifier with a cryptographically secure hash function, hashing the context from the protocol and the previous message sent by the prover.

### Computing the challenge and seeding the commitment {#sec:fs-challenge}

Relying on a hash function allows us to both compute the challenge and generate the commitment securely. We define the following auxiliary variables that may be pre-computed during the call of `SigmaProtocol.new(ctx, Y)`. All variables will have fixed length `DIGEST_LEN` so to avoid canonization attacks.

#### Seeding the commitment

The method `SigmaProtocol.prover_commit()` is a randomized function that generates a random element, unique per each execution. The commitment _should_ be seeded as follows:

If the output length `DIGEST_LEN` of the hash function is not sufficient to provide enough entropy for the commitment, the seed may be expanded with a PRNG to provide the quantity of random bytes desired.

#### Computing the challenge

The method `SigmaProtocol.challenge(T)` is implemented as follows in order to produce a random challenge.

This method is fixed for all implementations of `SigmaProtocol`. Note that the state of the hash function is partially shared between the commitment seed inputs and the challenge computation. Implementors may choose to store the partial hash state before generating the commitment, and reuse it when computing the challenge.

### Non-interactive proofs

We define two _public methods_ for generating proofs, meant to be exposed externally: `short_proof`, and `batchable_proof`. Since the challenge is computed deterministically from the commitment and the statement, it is not necessary to include the full transcript in a proof, as it can be deduced in the verification phase.

Short proofs are the most efficient if the protocol contains at least an _AND_ composition, and the gain in size is measured as `|T_vec| - DIGEST_LEN`. (Note: the length of the commitment is the length of the statement.) Batchable proofs are the canonical forms of proofs. Provers in the batchable form may raise an exception if the statement is not valid. Proofs are seen as fixed-length bit strings, whose exact length can be inferred from the statement during initialization of the Sigma protocol.

::: remark
Witness validation In the following we assume correctness of the witness `w` for the given statement `Y`. This can be ensured, e.g., by a higher-level application, or by running
`SigmaProtocol.verifier(T, c, s)` before sending the resulting proof.
:::

### Batchable Proofs

Prover algorithm.

    SigmaProtocol.batchable_proof(w)

    (T_vec, pstate) = SigmaProtocol.prover_commit(w)
    c = SigmaProtocol.challenge(T)
    s_vec = SigmaProtocol.prover_response(pstate, c)
    return (Serialize(T_vec), Serialize(s_vec))

The challenge `c` is not provided within a batchable proof since it can be re-computed from the commitment.

Verifier algorithm.

    SigmaProtocol.batchable_verify(proof)

    (T, s) = Deserialize(proof)
    c <- SigmaProtocol.challenge(T)
    return SigmaProtocol.verifier(T, c, s)

**WARNING**
Input validation The case of batched verification must include an input validation sub-routine that asserts the statement and commitments are in question. In the case of elliptic curves, this boils down to point validation. Failure to properly check that a commitment is in the group could lead to subgroup attacks [@EC:VanWie96; @C:LimLee97] or invalid curve attacks [@C:BieMeyMul00; @RSA:BBPV12].

### Short Proofs {#sec:shortproof}

Prover algorithm.

    SigmaProtocol.short_proof(w)

    (T, pstate) <- SigmaProtocol.prover_commit(w)
    c <- SigmaProtocol.challenge(T)
    s_vec <- SigmaProtocol.prover_response(pstate, c)
    return (Serialize(c), Serialize(s))

The commitment `T` is not provided within a short proof since it can be calculated again.

Verifier algorithm.

    SigmaProtocol.short_verify(proof)

    (c, s) = Deserialize(proof)
    T <- SigmaProtocol.simulate_commitment(c, s)
    expected_c <- SigmaProtocol.challenge(T)
    return (c == expected_c)

If input parsing fails, an exception should be raised. If verification
fails, an exception should be raised. Otherwise, the verifier outputs
`True`. Optionally, the implementation can choose to return the
parsed statement.

::: remark
Availability of the short form While the short form as described here is
applicable to all Sigma protocols currently covered by this document,
it cannot be used for protocols where `T` is not uniquely determined by
`c` and `s`, as is the case, e.g., for ZKBoo [@USENIX:GiaMadOrl16],
one-out-of-many proofs [@EC:GroKoh15], or protocols, where a randomized
signature is sent and proven correct subsequently, e.g.,
[@RSA:PoiSan16; @AC:CamChaShe08].

A trade-off is presented, e.g., by Bobolz et al. [@EPRINT:BEHF21],
requiring an additional algorithm to shorten a full transcript to a
compressed form which still allows for unique reconstruction of the
transcript.
:::

## Input validation

TODO TODO TODO

# Sigma protocols on elliptic curves {#sec:instantiation}

The following section now presents concrete instantiations for of
Sigma protocols over elliptic curves.

::: remark
Protocols for residue classes Because of their dominance, the
presentation in the following focuses on proof goals over elliptic
curves, therefore leveraging additive notation. For prime-order
subgroups of residue classes, all notation needs to be changed to
multiplicative, and references to elliptic curves (e.g.,
`curve`) need to be replaced by their respective counterparts
over residue classes.
:::

## Ciphersuite Registry

We advise for the use of prime-order elliptic curves of size either 256
or 512 bits, depending on the desired security of the upper layers in
the protocol[^2].

::: center
  Curve       Identifier        Security Level           Sources
  ----------- ---------------- ---------------- -------------------------
  P-521       `'-p-521'`             256                [@fips2]
  P-256       `'-p-256'`             128                [@fips2]
  secp256k1   `'-secp256k1'`         128                 [@SECG]
  Ristretto   `'-ristretto'`         128         [@cfrg-ristretto-decaf]
  BLS12-381   `'-bls12-381'`         128                [@bls12]
:::

We denote with `GG` the prime-order elliptic curve group, with
`GF(p)` the scalar field, and with `G` the generator of `GG` chosen as
per the curve parameters. We assume that all above curve parameters also
provide the following group operations: check for equality, identity,
addition, and scalar multiplication. Optionally, implementation might
implement Pippenger's algorithm [@pippenger] for multi-scalar
multiplication. In addition, we consider:

- an identifier for the curve, chosen from the table above, and
    denoted `curve`;

- a deterministic sub-procedure `a = FromBytes(b)`,
    taking as input a bit string `b` of length
    32 bytes, and mapping it into an element
    `a <-$- GF(p)`;

- a deterministic sub-procedure `s = Serialize(P)`,
    taking as input a group element `P in GG` and returning a
    fixed-length sequence of bits. For elliptic curve groups,
    `Serialize` must provide a compressed representation of the
    _affine_ representation, such as the `x`-coordinate of `P` and one
    bit determining the sign of `Y`.

- a deterministic sub-procedure `P = Deserialize(s)`,
    taking a (fixed-length and curve-dependent) sequence of bits and
    returning an elliptic curve point. This procedure may raise an
    exception or output `None` if the conversion fails.

## Maurer proofs {#sec:basic_sigma}

We describe an abstract class for proving knowledge of a preimage under
an arbitrary _group homomorphism_, which is a mapping between two groups
respecting the structure of the groups. In particular, as will be
discussed in #sec:instantiations, many statements related to discrete
logarithms or representations in groups of prime order, can be expressed
as statements over group homomorphisms. For an in-depth discussion of
the underlying theory we refer to Cramer [@cramer97].

**Definition 1**. For two groups `GG_1, GG_2`, a function
`\varphi:GG_1 -> GG_2:x\mapsto\varphi(x)` is a *(group) homomorphism*,
if and only if for all `a, b in GG_1` it holds that
`\varphi(a+b)=\varphi(a)+\varphi(b)`.
:::

Readers not familiar with the notation of group homomorphism may think
of `\varphi` as a linear function from `n` elements into `m` elements.

::: example
Discrete logarithm equality `phi_DLEQ` Looking at the relation
R_DLEQ, the relevant homomorphism is given by:
`f_DLEQ : GF(p) ->  GG^2 : w\mapsto (wG, wH)`
If equality of discrete logarithms within _different_ groups of the same
prime order `p` is to be proven, the homomorphism to be considered would
be:
`f_DLEQ' : GF(p) -> GG_1\timesGG_2 : w\mapsto (wG, wH)`
where `G` and `H` would now be generators for `GG_1` and `GG_2`,
respectively. All the techniques discussed in the remainder of this spec
equally apply to both cases.
:::

::: example
Representation phi_REP Looking at the relation
`{R_rep}`, the relevant homomorphism is given by:

  \varphi_rep : GF(p)^2 -> GG : (w_1, w_2)\mapsto w_1 G + w_2 H.

:::

We provide a generic template
for all Sigma protocols for statements of the following form over
DLOG groups:

  R_dl = {
    ((Y_1, ... , Y_m), (w_1, ... , w_n)) in GG^m * GF(p)^n: (Y_1, ... , Y_m)=\varphi(w_1, ... , w_n)
  }

where `\varphi:GF(p)^n -> GG^m` is a group homomorphism.

::: remark
Selective disclosure of witnesses Note that in the following
descriptions, all witnesses are assumed to be kept secret, i.e., none of
them is disclosed to the verifier. In case it is required to disclose
`w[j]`, as is the case, e.g., in the context of attribute-based
credential systems, the relation to be proven can be rewritten as
follows:

  R_dl'= {
    \begin{array}{r}
    ((Y_1', ... , Y_m')), (w_1, ... , w_{j-1}, w_{j+1}, ... , w_n)) in GG^m \times GF(p)^{n-1}: ~~~~~~~~~~~~\\
    (Y_1', ... , Y_m')=\psi(w_1, ... , w_{j-1}, w_{j+1}, ... , w_n)
    \end{array}
    }

where

    (Y_1', ... , Y_m') = (Y_1, ... , Y_m)-\varphi(0, ... , 0, w[j], 0, ... , 0)\text{ and}\\
      \psi(w_1, ... , w_{j-1}, w_{j+1}, ... , w_n) = \varphi(w_1, ... , w_{j-1}, 0, w_{j+1}, ... , w_n).

However, the following *defines neither the morphism nor the label
associated to the protocol*. These will be defined later in the specific
protocols.

- `DlogTemplate.new(ctx, Y_vec)`
    internally stores `Y_vec` and `ctx`.

-

    (T_vec, pstate) <- DlogTemplate.prover_commit(w_vec)

    sample random elements r_1, ... , r_n <- GF(p)
    T_vec =(T_1, ... , T_m)=\varphi(r_1, ... , r_n)
    pstate = (r_1, ... , r_n)
    return (T_vec, pstate)

-

    s_vec <- DlogTemplate.prover_response(pstate, c):
    (r_1, ... , r_n)= pstate
    (w_1, ... , w_n)= w_vec
    e = FromBytes(c)
    for i = 1, ... , n: s_i = r_i + e * w_i
    return s_vec = (s_1, ... , s_n)

- `DlogTemplate.label()` return
    `morphism_label()`.

-

    DlogTemplate.verifier(T_vec, c, s_vec)

    (s_1, ... , s_n) = s_vec
    (T_1, ... , T_m) = T_vec
    e = FromBytes(c)
    for i = 1, ... , n: check s_i in GF(p)
    for j = 1, ... , m: check T[j] in GG
    return ((T_1 + eY_1, ... , T_m + eY_m) = \varphi(s_1, ... , s_n))

-

    s_vec = DlogTemplate.simulate_response()

    sample random elements `s_1, ... , s_n <-`-GF(p)$
    return `(s_1, ... , s_n)`

-

    T_vec <- DlogTemplate.simulate_commitment(c, s_vec)

    (Y_1, ... , Y_m) = Y_vec
    (s_1, ... , s_n) = s_vec
    e = FromBytes(c)
    (T_1, ... , T_m) = \varphi(s_1, ... , s_n) - e*(Y_1, ... , Y_m)
    return T_vec = (s_1, ... , s_n)

## Linear relations {#sec:linear_relations}

While the above protocol allows one to efficiently prove knowledge of a pre-image under a homomorphism, many protocols found in the literature require one to prove relations among witnesses. Specifically, they require to prove relations like the following:

    R_lin = {
      ((Y_1, ... , Y_m), (w_1, ... , w_n)) :
      \begin{array}{c} (Y_1, ... , Y_m)=\varphi(w_1, ... , w_n) \\
                  A*(w_1, ... , w_n)^ in tercal = (b_1, ... , b_k)^ in tercal\end{array}},

where the matrix `A in GF(p)^{k\times n}` and vector
`(b_1, ... , b_k) in GF(p)^k` specify the system of linear equations.

In the following, we sketch how such relations can be translated into
relations of the form discussed in (#sec:basic_sigma). We assume that `A` is of the following
form:

    A = \left(\begin{array}{cccccccc}
      a_{11}     & ...       & a_{1k}    & 1         & 0       & 0     & ...    & 0\\
      a_{21}     & ...       & a_{2k}    & 0         & 1       & 0     & ...    & \vdots\\
      \vdots     &             & \vdots    & \vdots    &         & \vdots&          & 0\\
      \vdots     &             & \vdots    & \vdots    &         & 0     & 1        & 0\\
      a_{k1}     & ...       & a_{kk}    & 0         & ...   & ... & 0        & 1\\
    \end{array}\right)

Note that this is without loss of generality.
If the system of linear equations has a different form, the above form
can always be achieved using Gaussian elimination [@shoup08 Sec. 14.4]
and re-ordering of the witnesses. Note that we only need to consider the
case where `k<n`, as otherwise the linear equations would uniquely
determine the witnesses, which is not desirable in our context.

The following relation `{R_lin}'` is now
equivalent to that specified by `{R_lin}`:

  R_lin' = {
    ((Y_1, ... , Y_m), (w_1, ... , w_{n-k})) :
        (Y_1, ... , Y_m) = \psi(w_1, ... , w_{n-k})
  }

where

  \psi(w_1, ... , w_{n-k}) = \varphi(w_1, ... , w_{n-k}, -\sum_{i = 1}^{n-k}a_{1i}w_i, ... , -\sum_{i = 1}^{n-k}a_{ki}w_i)\text{ and}\\
  (Y_1', ... , Y_m')   = (Y_1, ... , Y_m) - \varphi(0, ... , 0, b_1, ... , b_k).

## Examples {#sec:instantiations}

Let `GG` be a group over an elliptic curve with prime order `p`. Denote
with `G in GG` a generator of `GG`.

### Schnorr signatures {#sec:instantiations:schnorr}

Schnorr signatures prove knowledge of the discrete logarithm `w in  GF(p)` of a point `Y = wG` in
base `G`.

- `\varphi:GF(p) -> GG:w -> wG`

- `Schnorr.morphism_label()`: return:

    ???


For a description of this proof goal in the general case of residue
classes, we also refer to [@zkproof-reference 1.4.1].

### Discrete logarithm equality

So-called DLEQ proofs prove equality of the discrete logarithm, that is:
`Y_1 = wG` and `Y_2 = wH`.

- `\varphi:GF(p) -> GG^2:w\mapsto (wG, wH)`

- `Dleq.morphism_label()`: return

    ??

### Diffie-Hellman

Let `GG` be a group over an elliptic curve with prime order `p`.
Proving knowledge of the exponents of a valid Diffie-Hellman triple
means proving knowledge of `w_1, w_2 in GF(p)` such that `Y_1= w_1G`,
`Y_2= w_2G`, and `Y_3= w_1 w_2 G`. The mapping
`GF(p)^2 -> GG^3:(w_1, w_2)\mapsto (w_1G, w_2G, w_1w_2G)` is not a
homomorphism, and consequently the basic protocol presented before
cannot be deployed directly. However, the required multiplicative
relation can be proven by observing that the proof goal is equivalent to
`Y_1= w_1G`, `Y_2= w_2G`, and `Y_3= w_2Y_1`, leading the homomorphism

- `\varphi:GF(p)^2 -> GG^3:(w_1, w_2)\mapsto(w_1G, w_2G, w_2Y_1)`

- `Dh.morphism_label()` return:

    ??

As shown in this example, and in contrast to linear relations,
multiplicative relations among witnesses typically require a
reformulation of the proof goal.

### Representation {#sec:instantiations:representation}

Let `GG` be a group over an elliptic curve of prime order `p`, and let
`G_1, ... , G_m` be generators of `GG`. Proving knowledge of a valid
opening of a Pedersen commitment means proving knowledge of
`w_1, w_2, ... , w_m in GF(p)` such that
`Y = w_1G_1 + w_2G_2 + ... + w_m G_m`.

- `\varphi:GF(p)^m -> GG:(w_1, w_2, ... , w_m)\mapsto \sum_i w_iG_i`

- `Rep.morphism_label()` returns

    \hash({representation}, ~{curve}\mathbf{\mid}~`Serialize(G_1) , ~*s , ~`Serialize`(G_m) , ~`Serialize`(Y))`$

::: example
Range proofs via bit decomposition Let `GG` be a cyclic group of prime
order `p`, and let `G` and `H` be generators of `GG`, and let `\ell` be
a non-negative integer satisfying `\ell<\log_2 p`. Consider the
following relation:

  R_range = \set{\left(Y, (w_1, w_2))\right)~:~Y = w_1 G +w_2 H ~\land~ w_1 in [0, 2^\ell)

Multiple techniques for proving that a secret witness lies within a
certain range, cf. Morais et al. [@range-proof-survey] for a survey. We
will use the so-called _bit decomposition_ approach.

To do so, the prover computes `w_{1, i} in \set{0, 1}` for
`i =0, ... , \ell-1` such that `w_1=\sum_{i =0}^{\ell-1}2^iw_{1, i}`, and
computes commitments to those individual bits, i.e.,
`Y_i = w_{1, i}G+w_{2, i}H` for `w_{2, i} <-`- GF(p)$. Furthermore, it sets
`w^*= w_2-\sum_{i =0}^{\ell-1}2^iw_{2, i}`.

Assuming that the discrete logarithm problem is hard in `GG`, the above
relation is now equivalent to the following relation:

      {R_range}' = \bigg\{\left((Y, (Y_i)_{i =0}^{\ell-1}), (w_1, w_2, (w_{2, i})_{i =0}^{\ell-1}), w^*)\right)~:~         Y = w_1 G +w_2 H ~\land~ \\
        Y-\sum_{i =0}^{\ell-1} 2^iY_i = w^* H ~\land~  \\
        \bigwedge_{i =0}^{\ell-1} \left(Y_i = w_{2, i}H ~\lor~ Y_i-G = w_{2, i}H\right)\bigg\}.

It can now be seen that the above ensures knowledge of the witnesses `w_1`
hidden within `Y`. Furthermore, we guarantee that the values hidden within
`Y_i` correctly add up to `w_1`, i.e., that
`w_1-\sum_{i =0}^{\ell-1}2^iw_{1, i}=0`. Finally, the two clauses
ensure that each `Y_i` is a commitment to
either `0` or `1`, thus implying the bound on `w_1`.

The different clauses can
finally be composed using nested protocol compositions from
(#sec:composition).
:::

## Batch verification

The batchable form can take advantage of the following fact. Given
`\ell` verification equations of the form:

  T_i + c_i Y_i = \sum[j] s[j] G_{i, j}

for `i = 1, ... , \ell`, the
verifier can sample a random vector of coefficients
`a_vec in GF(p)^\ell` and instead test:

  \left(\sum_{i = 1}^{\ell} a_i T_i\right) + \left(\sum_{i = 1}^{\ell} a_i *  c_i Y_i \right) = \left(\sum_{i = 1}^{\ell} a_i * \sum[j] s[j] G_{i, j}\right).

If the matrix `G_{i, j}` of generators has identical rows, by linearity
the right-hand side can be computed as a single scalar product. If the
statements `Y_i`'s have identical rows, by linearity the second term in
the equation can be computed as a single scalar product.

In any case, the test can be efficiently implemented as a single
multi-scalar multiplication, minimizing the number of group operations
needed:

    \left(\sum_{i = 1}^{\ell} a_i T_i\right) + \left(\sum_{i = 1}^{\ell} (a_i *  c_i) Y_i \right) + \left(\sum_{i = 1}^{\ell}\sum[j] (-a_i *  s[j]) G_{i, j}\right) = 0

The random vector `a_vec` can be _deterministically_ generated by
fixing `a_1 = 1` and setting
`(a_2, ... , a_{\ell}) =\prg(H(c, s_vec))` [@bip-schnorr].

# Composing the same relation

# Encoding the statement

Statements in Sigma protocols take the form of a labeled binary tree:
`Statement` is either:

- a label _AND_, or _OR, and two children _left_ and _right_ of type `Statement`
- a `StatementLeaf` instance. Objects of this type depend on the specific algebraic setting used, and will be treated later.

Statements are serialized depth-first. There are many different options
for serialization that could be considered:

- Concise Binary Object Representation (CBOR)
    [RFC7049](https://datatracker.ietf.org/doc/html/rfc7049)
- The zk proof Reference document provides a serialization document
    for r1cs [@zkproof-reference 3.4.2], but there is nothing in it.

# Composition of Sigma Protocols {#sec:composition}

Sigma protocols can be composed to prove knowledge of multiple independent witnesses (_AND composition_), and for proving knowledge for one out of a set of witnesses (_OR composition_).
An object `SigmaProtocol` can be seen as a recursive enumeration

        enum SigmaProtocol {
          AndComposition {left: SigmaProtocol, right: SigmaProtocol},
          OrComposition  {left: SigmaProtocol, right: SigmaProtocol},
          [...]
        }

whose instances expose the methods described above. The dots `[...]`
denote (optional) Sigma protocols instantiations that will be covered later.
Without loss of generality, the techniques
presented in the following focus on the composition of two protocols.
Composition of multiple protocols (e.g., proving knowledge of a witness
for one out of many statements) can be achieved by recursively applying
composition of two protocols.

### AND Composition

In this section we show how to construct a Sigma protocol proving
knowledge of multiple independent witnesses, e.g., knowledge of multiple
secret keys, or openings to multiple commitments. That is, a
Sigma protocol for the following relation:

    R_and = {
      ((Y_0, Y_1), (w_0, w_1) : (Y_0, w_0) in R_0 AND (Y_1, w_1) in R_1
    }

For the rest of this section, the witness `w` for the Sigma protocol
will now be a pair `(w_0, w_1)` of witnesses, and the associated
statement `Y` will be a pair `(Y_0, Y_1)` of statements, where `w_0` is
the witness for the statement `Y_0`, and `w_1` is the witness for `Y_1`.

Intuitively, the AND composition simply runs the instances of the
different protocols to be composed in parallel, using the same challenge
`c` for both instances. The verifier will then accept the protocol run,
if and only if all instances of the partial protocols output `True`.

The resulting Sigma protocol is specified by the following
algorithms:

-

    `AndComposition.new(ctx, left, right)`: internally store `left` and `right`.

-

    (T_vec, pstate) <- AndComposition.prover_commit(w_vec)
    (w_0, w_1) = w_vec
    (T_0, pstate_0) <- left.prover_commit(w_0)
    (T_1, pstate_1) <- right.prover_commit(w_1)
    return (T_vec, pstate) = ((T_0,  T_1), (pstate_0, pstate_1))

-

    s_vec <- AndComposition.prover_response(pstate, c)

    (pstate_0, pstate_1)= pstate
    s_0 <- left.prover_response(pstate_0, c)
    s_1 <- right.prover_response(pstate_1, c)
    return s_vec = (s_0, s_1)

-

    AndComposition.verifier(T_vec, c, s_vec)

    (s_0, s_1)= s_vec
    return (left.verifier(T_0, c, s_0) and right.verifier(T_1, c, s_1))

-

  `AndComposition.label()` is computed as:

      H(({and-composition}\mathbf{\mid}~`left.label()` , ~`right.label()`)

    The supported hash functions are described in [@draft-orru-zkproof-fs].

-

    AndComposition.simulate_response()

    s_0 <- left.simulate_response()
    s_1 <- right.simulate_response()
    return s_vec = (s_0, s_1)

-

    AndComposition.simulate_commitment(c, s_vec)

    (s_0, s_1) = s_vec
    T_0 <- left.simulate_commitment(c, s_0)
    T_1 <- right.simulate_commitment(c, s_1)
    return T_vec = (T_0, T_1)

::: warning
Witness equality Note that the AND-composition defined in the following
gives no guarantee about equality of the witnesses: if the same witness
is used across different clauses of the AND-composition, the protocol
will not guarantee that they are indeed the same.
How to achieve such claims is discussed in (#sec:linear_relations).
:::

## OR Composition

In the following we explain how to construct a Sigma protocol proving
knowledge of one out of a set of witnesses, for instance one of a set of
secret keys (like ring signatures). That is, the algorithms specified
below constitute a Sigma protocol for the following relation:

    R_or = {
        ((Y_0, Y_1), (w_0, w_1) :
        (Y_0, w_0) in  R_0 OR (Y_1, w_1) in R_1
    }

The statement `Y` is the pair `(Y_0, Y_1)` of the composing statements,
and the witness `w` is the pair `(w_0, w_1)` of the witnesses for the
respective relation. One of the witness can be set to `None`.
In the following protocol specification, let `j` be such that `w[j]` is
known to the prover, whereas without loss of generality `w[1-j]` is
assumed to be unknown to the prover.

On a high level, the protocol works as follows. Using the simulator, the
prover first simulates a transcript for the unknown witness (keeping the
challenge and response of this transcript temporarily secret), and
generates an honest commitment for the known witness. Having received
the challenge, the prover then computes challenge for the known witness,
depending on the received challenge and the one from the simulated
transcript. Having computed the response, the prover transfers the
responses of both transcripts, as well as the partial challenges to the
verifier, who accepts if and only if both instances of the partial
protocols output `True` and the partial challenges correctly add up
to the random challenge.

The main procedures of the resulting Sigma protocol are specified by
the following algorithms:

- `OrComposition.new(ctx, left, right)`:
    internally store `left` and `right`.

-

    OrComposition.prover_commit(w_vec)

    Prover = [left, right]
    (w_0, w_1) = w_vec, and let j in [0, 1] be the first index for which w[j] != None
    (T[j], pstate[j]) <- Prover[j].prover_commit(Y[j], w[j])
    s[1-j] <- Prover[1-j].simulate_response()
    choose a random c[1-j] in \mathcal{C}
    T[1-j] <- Prover[1-j].simulate_commitment(c[1-j], s[1-j])
    return (T_vec, pstate) = ((T_0, T_1), (pstate[j], c[1-j], s[1-j]))

-

    OrComposition.prover_response(pstate, c)

    (pstate[j], c[1-j], s_[1-j])= pstate
    c[j]= c XOR c[1-j]
    s[j] <- Prover[j].prover_response(pstate[j], c[j])
    return s_vec = (s_0, s_1, c_0)

-

    OrComposition.verifier(T_vec, c, s_vec)

    (s_0, s_1, c_0) = s_vec
    c_1= c\oplus c_0
    return (left.verifier(T_0, c_0, s_0) and right.verifier(T_1, c_1, s_1))

- `OrComposition.label()` is computed as:

      H(({or-composition}\mathbf{\mid}~`left.label()` , ~`right.label()`)


-

    sOrComposition.simulate_response()

    (Y_0, Y_1) = Y_vec
    s_0 <- left.simulate_response()
    s_1 <- right.simulate_response()
    choose a random `c_0` in $\mathcal{C}
    return s_vec = (s_0, s_1, c_0)

-

    T_vec <- OrComposition.simulate_commitment(c, s_vec)

    (s_0, s_1, c_0) = s_vec
    c_1 = c XOR c_0
    T_0 <- left.simulate_commitment(c_0, s_0)
    T_1 <- right.simulate_commitment(c_1, s_1)
    return T_vec = (T_0, T_1)

# Additional proof types

Other protocols are not included here and are not part of the scope of
the current version of this spec.

- mpc-in-the-head protocol such as ZKBoo [@USENIX:GiaMadOrl16]

- one-out-of-many proofs such as [@EC:GroKoh15]

- lwe-based sigma protocol [@C:AttCraKoh21]

- syndrome decoding and LPN [@C:Stern93; @AC:JKPT12]

# Test vectors

[^2]: For instance, proving a DH relation with one fixed group element
    such as a public key, might expose the protocol to cryptanalytic
    attacks such as Brown-Gallant [@EPRINT:BroGal04] and Cheon's
    attack [@EC:Cheon06], and some implementations might opt for larger
    curve sizes. We consider these attacks out of scope for this
    standardization effort, and believe this analysis should be deferred
    to the concrete security study of the larger protocol.

# Acknowledgments
{:numbered ="false"}

Jan Bobolz, Mary Maller, Ivan Visconti, Yuwen Zhang.
