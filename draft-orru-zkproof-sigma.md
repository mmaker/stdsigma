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

normative:

informative:

--- abstract

This document describes Sigma protocols, a secure, general-purpose non-interactive zero-knowledge proof of knowledge. Concretely, the scheme allows proving knowledge of a witness, without revealing any information about the undisclosed messages or the signature itself, while at the same time, guarantying soundness of the overall protocols.

--- middle


## Constraint representation


Traditionally, proof system are defined in Camenish-Stadtler notation as (for example):

    VRF = {
      (x),            // Secret variables
      (A, B, G, H),   // Public group elements
      A = x * B,      // Statements to prove
      G = x * H
    }

A Schnorr constraint is represented as:

    struct ConstraintSystem {
        label: String                            // A label associated to the proof
        equations: [Equations; num_equations]    // the list of equations to be proven

        num_terms: usize                         // the number of secret scalars
        num_equations: usize                     // the number of equations to be proven
        points: Vec<Point>                       // the group elements to be used in the proof
    }


// call them statements
where `Equation` is the following type:

    struct Equation {
        // An index in the list of generators representing the left-hand side part of the equation
        lhs: usize
        // A list of (ScalarIndex, PointIndex) referring to a scalar and a generator
        rhs: Vec<(usize, usize)>
    }

A witness is defined as:

    struct Witness {
        scalars: [Scalar; num_terms] // The set of secret scalars
    }

For those familiar with the matrix notation, `SchnorrCS` is encoding a sparse linear equation of the form `A * scalars = B`, where `A` is a matrix of `num_equations` rows, `scalars.len` columns, of group elements. Each element is identified by a pair `(usize, usize)` denoting the column index, and the value (an index referring to `generators`).
The vector `B` is a list of indices referring to `generators`.


This is equivalently done with a constraint system:

    cs = ConstraintSystem.new("VRF")
    [x] = cs.allocate_scalars(1)
    [A, B, G, H] = cs.allocate_points(4)
    cs.append_equation(lhs=A, rhs=[(x, B)])
    cs.append_equation(lhs=G, rhs=[(x, H)])

In the above, `ConstraintSystem.new()` creates a new `ConstraintSystem` with label `"VRF"`.

    class ConstraintSystem:
        def new(label):
            return ConstraintSystem {
                label,
                num_equations: 0,
                num_terms: 0,
                points: [],
            }

        def allocate_scalars(self, n: usize):
            indices = range(self.num_terms, self.num_terms + n)
            self.num_terms += n
            return indices

        def allocate_points(self, n: usize):
            indices = range(len(self.points), len(self.points)
            self.points.extend([None; self.indices])
            return indices

        def assign_point(self, ptr: usize, value: Point):
            self.points[ptr] = value

        def append_constraint(self, lhs, rhs):
            equation = Equation {lhs, rhs}
            self.num_equations += 1
            self.equations.append(equation)

## Nonce and challenge derivation

Two types of randomness are needed for a sigma protocol:
1. A nonce seeding the randomness used to produce the commitment of the first round of the protocol
2. A challenge representing the verifier's public random coin.

The challenge of a Schnorr proof is derived with

    challenge = sho.init(iv).absorb_points(commitment).squeeze_scalar(1)


This can be generated with:


    nonce = sho.init(iv)
               .absorb_bytes(random)
               .ratchet()
               .absorb_scalars(witness)
               .squeeze_scalars(cs.num_terms)


The `iv`, which must properly separate the application and the statement being proved, is described below.


### Statement generation

Let `H` be a hasher object. The statement is encoded in a stateful hash object as follows.

    hasher = H.new(domain_separator)
    hasher.update_usize([cs.num_equations, cs.num_terms])
    for equation in cs.equations:
      hasher.update_usize([equation.lhs, equation.rhs[0], equation.rhs[1]])
    hasher.absorb_points(generators)
    iv = hasher.digest()

In simpler terms, without stateful hash objects, this should correspond to the following:

    bin_challenge = SHAKE128(iv).update(commitment).digest(scalar_bytes)
    challenge = int(bin_challenge) % p

and the nonce is produced as:

    bin_nonce = SHAKE128(iv)
                .update(random)
                .update(pad)
                .update(cs.scalars)
                .digest(cs.num_terms * scalar_bytes)
    nonces = [int(bin_nonce[i*scalar_bytes: i*(scalar_bytes+1)]) % p
              for i in range(cs.num_terms-1)]


Where:
    - `pad` is a (padding) zero string of length `168 - len(random)`.
    - `scalar_bytes` is the number of bytes required to produce a uniformly random group element
    - `random` is a random seed obtained from the operating system memory

## Proof generation





# Acknowledgments
{:numbered ="false"}

Jan Bobolz, Stephan Krenn, Mary Maller, Ivan Visconti, Yuwen Zhang.
