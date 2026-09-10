/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Alg
public import Leancrypto.Der
public import Libcrypto.Hash

/-!
The tables carrying `jose`'s vocabulary into OpenSSL's. `Jose.Alg.scheme` is the only place an
algorithm names a digest, a curve or a salt length; everything here starts from what it named, so
this package has no second opinion about any of them.
-/

@[expose] public section

namespace Jose.Libcrypto

/-- Exhaustive with no default case, so a digest added to `Leancrypto.Sha2` stops this compiling
rather than being silently mapped onto one of the three below. -/
def digest : Leancrypto.Sha2 → Libcrypto.Hash.Algorithm
  | .sha256 => .sha256
  | .sha384 => .sha384
  | .sha512 => .sha512

/-- The curve identifiers RFC 5480 §2.1.1.1 registers, which is what a `SubjectPublicKeyInfo` names
the curve by. -/
def curveOid : Crv → ByteArray
  | .p256 => Leancrypto.Der.prime256v1Oid
  | .p384 => Leancrypto.Der.secp384r1Oid
  | .p521 => Leancrypto.Der.secp521r1Oid

/-- Whether the salt length a scheme carries is the length of its digest, which is what
`Libcrypto.Sign.PssSaltLength.digest` asks OpenSSL for. RFC 7518 §3.5 pins the two together, and
the suite proves this answers `true` for every algorithm, so that value is checked rather than
assumed. -/
def saltMatchesDigest : Scheme → Bool
  | .pss hash saltLength => saltLength == hash.size
  | _ => true

end Jose.Libcrypto
