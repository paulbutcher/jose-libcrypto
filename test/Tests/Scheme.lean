/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import JoseLibcrypto

/-!
The one claim about the scheme table that no vector could establish. It compiles or it does not, so
it needs no entry in the runner.
-/

namespace Tests.Scheme
open Jose

/-- Every PSS algorithm asks for a salt as long as its digest, which is what this backend tells
OpenSSL by naming `Libcrypto.Sign.PssSaltLength.digest` rather than a length of its own. RFC 7518
§3.5 requires exactly that, and were the two ever to part, a signature made here would carry a salt
the standard does not allow while nothing in the types complained; this is what stops that reaching
a release.

`Jose.Libcrypto.saltMatchesDigest` answers `true` for a scheme that is not `.pss`, and for one that
is exactly when the salt length it carries equals the size of the digest it carries. The claim is
over `alg.scheme` for every `alg`, and `cases` enumerates the algorithm type, so no algorithm is
left out and none is admitted by the `true` the other schemes take: the three `.pss` algorithms
reach the comparison, and it is their published salt lengths of 32, 48 and 64 that are compared
against the sizes of SHA-256, SHA-384 and SHA-512. That those sizes are the digests' true output
lengths is not proved anywhere; `leancrypto` checks it against the published vectors. -/
theorem pssSaltIsTheDigestLength (alg : Alg) : Libcrypto.saltMatchesDigest alg.scheme := by
  cases alg <;> rfl

end Tests.Scheme
