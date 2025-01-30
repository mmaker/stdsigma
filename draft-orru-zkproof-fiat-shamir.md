---
title: "Fiat-Shamir Heuristic"
category: info

docname: draft-orru-zkproof-fiat-shamir-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
# area: AREA
workgroup: Zkproof
keyword:
 - zero knowledge
 - hash
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "mmaker/stdsigma"
  latest: "https://mmaker.github.io/stdsigma/draft-orru-zkproof-fiat-shamir.html"

author:
 -
    fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"

normative:

informative:

--- abstract

This document describes the Fiat-Shamir transform.

--- middle

A stateful hash objects can absorb inputs incrementally and squeeze variable-length unpredictable messages.

## The API

- `SHO.init(iv) -> sho`, creates a new `sho` object with a description;
- `sho.absorb(state, values)`, absorbs a list of "native" elements (that is, elements in the same domain of the hash function);
- `sho.squeeze(length)`, squeezes from the  a list of "native" elements
- `sho.finalize()`, deletes the hash object safely.

## Sigma protocols example

Two hash states are needed, one public and one private for nonce generation. They are built as follows.

```
    iv  = SHA3-256(label)
    challenge = SHAKE128(iv || commitment)
    private_nonce = SHAKE128(iv || random || pad || witness)
```

# OLD TEXT TO INTEGRATE

# Introduction {#sec:fs}

We show how to perform Fiat-Shamir on any public-coin protocol, providing randomness for the prover and secure generation of random coins for the verifier. Informally, a non-interactive zero-knowledge proof constructed via the Fiat-Shamir heuristic, the verifier (random oracle) is replaced with a duplex sponge. Messages from the prover are treated as `Absorb` calls, while challenges are treated as `Squeeze` calls. We will see this in detail below. Core features are:

- Support custom hash function, including algebraic hashes in a unified generic way.
- Retro-compatibility with the NIST API.
- Efficiency: minimizing the number of hash invocations while maintaining security, and (whenever possible) preprocessing information that is public or carried across protocols.
- Private randomness generation.
- The API makes it impossible to provide two different challenges for the same prover message. The prover's zk randomness is bound to the protocol transcript, without making the proof deterministic.

## Scope of this document

The protocol consists in:

- Generating a string encoding the sequence of input and output lengths (the IO pattern)
- An API absorbing and squeezing native elements (Arthur) that is initialized from the IO Pattern
- An API for generating private randomness securely (Merlin) that internally uses Arthur

## Syntax


# Ciphersuites

Different hash functions may rely on different constants. We define some of the parameters associated to the hash function that will be used throughout this spec.

DOMSEP
: Domain separator for this standard. Fixed to `zkpstd/0.1`

## Hash Registry {#sec:hash-registry}

This is the set of all supported hash functions. They take an arbitrary length sequence of bytes as input, and output 32 bytes of entropy.

| Hash function | `C` | `R` |
| blake2b [@ACNS:ANWW13] |
| sha3-256 [@EC:BDPA13]  |
| ??? |

Supported hash functions must all have `BLOCK_LEN` > 32. We define labels and constant strings so that their length is always at most 32 bytes. If `DIGEST_LEN` > 32, we implicitly assume that the implementation considers only the least significant bytes and discards the remainder of the hash output when exactly 32 bytes are needed.

# IO Pattern
 An IO pattern is a utf8-encoded string that specifies
the protocol in a simple, non-ambiguous, human-readable format. A
typical example is the following:

    domain-separator A32generator A32public-key R A32commitment S32challenge A32response

The domain-separator is a user-specified string uniquely identifying the end-user application (to avoid cross-protocol attacks).

The letter `A` indicates the absorption of a public input (an `Absorb`), while the letter `S` indicates the squeezing (a `Squeeze`) of a challenge.
The letter `R` indicates a ratcheting operation: ratcheting means invoking the hash function even on an incomplete block. It provides forward secrecy and allows it to start from a clean rate.

After the operation type, is the number of elements in base 10 that are being absorbed/squeezed.

Then, follows the label associated with the element being absorbed/squeezed. This often comes from the underlying description of the protocol. The label cannot start with a digit or contain the NULL byte.

Each operation is separated by the NULL byte.

The IO pattern string can be parsed as a queue of the form (Operation, Length), where consecutive Operations must be merged into one adding the length, and the length of ratchet operations is conventionally set to 0. The IO pattern above translated to the queue:


    (A, 64) (R, 0) (A, 32) (S, 32) (A, 32)


# Duplex Hash
In addition to the IO pattern, the protocol must also
designate a hash function.

We focus here on permutation functions, but already dispose of a generic bridging interface for the NIST API that we omit for now here. Fix a permutation function P (a valid choice here is keccak-f[1600]) acting on on R+C elements (called *native elements*), where `R` is called *rate* (for keccak-f[1600] this would be R=136), and `C` is the capacity (for keccak-f[1600] this would be C=64).

More specifically, we build a [duplex sponge in overwrite mode](https://en.wikipedia.org/wiki/Sponge_function#Overwrite_mode) placing the rate in the least significant indices. Note that this definition is generic over bytes or arbitrary fields and that the definition below is tail-recursive, and State is a mutable reference to the hash state.

    START(IV) -> State

    State = [0; C + R]
    for i = R .. R+C: State[i] = IV[i]
    squeeze_pos=absorb_pos=0

-

    Absorb(State, Input[])

    If Input is empty, set squeeze_pos=R
    If absorb_pos==R, let State=P(state); set absorb_pos=0 and run Absorb(State, Input[]).
    Else, State[absorb_pos]=Input[0]; absorb_pos+=1, recursively run
    Absorb(State, Input[1..]).

-

    Squeeze(State, Output[])

    If squeeze_pos==R, let State=P(State); set absorb_pos=0 and run Squeeze(State, Output[]).
    Else, Output[0]=State[squeeze_pos]; squeeze_pos+=1, recursively run Squeeze(State, Output[1..])

-

    RATCHET(State)

    Permute the state: State = P(State); zero the rate part of the state
    State[..R] = 0, set the counters squeeze_pos=absorb_pos=0.

-

    FINISH(State)

    Safely delete State

<!-- # Pover state

The API for generating non-interactive zero-knowledge proofs using the Fiat-Shamir transform as bytes.

The prover state consists of a public sponge denoted StatePub (generating the public randomness) and a duplex hash (generating the private instance) denoted StatePriv.

    START(IO) -> State
    Store the IO Pattern as a queue.
    Hash the IO pattern IO into 32 bytes (`Absorb` and `Squeeze`); use the
    result to initialize a duplex hash StatePub.

    Start a new duplex hash *for bytes*, absorbing IO as input StatePriv.
    Initialize a byte vector Transcript.
    Return State = (StatePub, StatePriv, Transcript)

-

    Absorb(State, Input[])

    Run `Absorb`_PUB(State, Input[])
    Append ByteInput into Transcript.

-

    Squeeze(State, Output[])

    Pop (or decrease) the head of the queue, throwing an error if Operation is not `S` or Length\<0. Squeeze Output[] elements from StatePub.

-

    RATCHET(State)

    Pop the head of the queue, throwing an error if Operation is not R.
    Run RATCHET(StatePub); RATCHET(StatePriv)

-

    FINISH(State)
    Throw an error if the queue is not empty.
    Run FINISH(StatePub); FINISH(StatePriv).
    Return Transcript

- this procedure is useful for absorbing public information known
    *outside* of the protocol, like the curve parameters

    Absorb_PUBLIC(State, Input[]) -> ByteInput
    Pop (or decrease) the head of the queue, throwing an error if Operation is not `A` or Length\<0.
    Serialize Input[] into bytes into a byte vector ByteInput.
    Absorb Input[] into StatePub.
    Return ByteInput.

- this procedure is useful for adding entropy to the prover, e.g.
hashing also the witness.

    Absorb_PRIVATE(State, ByteInput[])
    Absorb ByteInput[] into StatePriv. Run RATCHET(State)

-
    Squeeze_PRIVATE(State, N) -> OutputBytes[N]
    Let Seed be 32 bytes from the operating system randomness.
    Run RATCHET(State); Absorb(StatePriv, Seed)
    Return Squeeze(StatePriv, N).

*Important Note.* During the protocol, the implementation *MUST* make sure that the sequence of API calls reflect the sequence provided in the IO pattern. Calls to absorb should be associative to provide streaming functionalities, that is: `Absorb([a])`; `Absorb([b])` should be equivalent to `Absorb([a, b])`.

Same goes for `Squeeze`.

Roughly speaking, since the information about the length and the data type is provided in the IO pattern, during the protocol execution the hash is essentially just concatenating inputs without worrying about data length, separators, markers for the state, etc.

The framework can be used inside algebraic SNARKs without any online cost, since the IO pattern can be pre-computed outside of the circuit. Moreover, it is compatible with algebraic hashes, so protocol developers don't have to develop new forms of encoding for length and markers for each different field. Protocol composition can be achieved by simply concatenating IO patterns. Overall, the above API provides better efficiency and security for real-world protocols. -->

## Generating challenges

We offer the following API for the verifier of a non-interactive proof using the Fiat-Shamir heuristic. For the technical audience, this is essentially [SAFE](https://eprint.iacr.org/2023/522) with a byte interface.

-

    START(IO, Transcript) -> State
    Store the IO Pattern as a queue.
    Hash the IO pattern IO into 32 bytes ( `Absorb` and `Squeeze`); use the
    result to initialize a duplex hash State.

-

    READ(State, N) -> Input[N]
    Read the Transcript deserializing N elements until Input[] is filled.
    Absorb Input[]into the duplex hash.
    Pop (or decrease) the head of the queue, throwing an error if
    Operation is not `A` or Length\<0.

-

    Squeeze(State, N) -> Output[N]
    Squeeze Output[] elements from the duplex hash and return them
    Pop (or decrease) the head of the queue, throwing an error if
    Operation is not `S` or Length\<0.

-

    RATCHET(State)
    Invoke ratchet from the duplex hash and clear any additional state.
    Pop the head of the queue, throwing an error if Operation is not R.

-

    FINISH(State)
    Throw an error if the queue is not empty or Transcript is not fully read.
    Delete the state.

# Serialization and conversion of Elements

The above API only covers actions over native elements. Oftentimes, we want to send more complex structures. Note that it\'s important the encoding size of the elements is fixed and can be statically determined.

In the case of integers mod N to be encoded as bytes, the element is seen as an integer between 0 and N-1 encoded in big endian. Elliptic curve elements are encoded serializing the x coordinate with two bits to encode whether y is positive, negative, or infinity.

When squeezing bits from native elements mod N, the lowest L bits are guaranteed to be indistinguishable from uniformly random if

    L + 1 + N.bit_length() - (alpha := N % 2 ** n).bit_length() -(2 **
N - alpha).bit_length() >= 128

We require a potential function `Squeeze_BITS` to return the above number of bits and discard the remaining elements of the native squeezed elements.

# Additional Material

[Reference implementation](https://github.com/mmaker/nimue) (with examples), [Proofs of security](https://eprint.iacr.org/2023/520).
