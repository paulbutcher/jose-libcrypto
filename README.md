# jose-libcrypto

The native backend for [lean-jose](https://github.com/paulbutcher/lean-jose): ECDSA, EdDSA, and asymmetric signing, over OpenSSL through [lean-libcrypto](https://github.com/paulbutcher/lean-libcrypto).

`jose` is pure Lean and cannot reach elliptic curve arithmetic or a private key. This package supplies `Backend.libcrypto`, which provides full coverage:

| Algorithms | Verify | Sign |
| --- | --- | --- |
| `HS256` `HS384` `HS512` | yes | yes |
| `RS256` `RS384` `RS512` | yes | yes |
| `PS256` `PS384` `PS512` | yes | yes |
| `ES256` `ES384` `ES512` | yes | yes |
| `EdDSA` | yes | yes |

## Usage

```lean
require «jose-libcrypto» from git "https://github.com/paulbutcher/jose-libcrypto"
```

```lean
import JoseLibcrypto
open Jose

def policy : Policy :=
  { algs := #[.es256],
    issuer := "https://appleid.apple.com",
    audience := #["my-client-id"] }

def check (jwks token : String) : IO (Except Error Claims) := do
  match Jwks.parse {} jwks with
  | .error reason => return .error reason
  | .ok published =>
    match ← KeySet.ofJwks Backend.libcrypto published with
    | .error reason => return .error reason
    | .ok keys => Jwt.verifyNow Backend.libcrypto policy keys token
```

A key set is prepared once, when the set is read, rather than once per token.

### Signing

`jose` refuses a JWK carrying a private component, so a signing key comes from a file rather than from a JWKS. `PreparedKey.ofPkcs8` reads the unencrypted PKCS#8 that Apple hands you for Sign in with Apple, and `PreparedKey.ofPem` the same key in its PEM armour.

```lean
def assertion (pkcs8 : ByteArray) (claims : String) : IO (Except Error String) := do
  match ← Libcrypto.PreparedKey.ofPkcs8 pkcs8 with
  | .error reason => return .error reason
  | .ok key => Jws.token Backend.libcrypto .es256 key "{\"alg\":\"ES256\"}" claims
```

An `EncryptedPrivateKeyInfo` does not decode: `lean-libcrypto` binds no passphrase callback, so an encrypted key arrives as the same refusal as any other bytes that are not a `PrivateKeyInfo`. Decrypt it before reading it.

## What is verified

Proved as a theorem, for all inputs, in `test`:

- Every PSS algorithm asks for a salt as long as its digest, which is what this backend tells OpenSSL by naming `PssSaltLength.digest` rather than a length of its own. RFC 7518 §3.5 requires that, and were the two to part, a signature made here would carry a salt the standard does not allow.

Checked against published vectors, not proved:

- RFC 7515 A.3 and A.4 verify, and return the payloads those appendices sign. These are the ECDSA vectors `jose` could not run. A.4 is P-521, whose coordinates are 66 bytes while its digest is 64, so it is the one that catches a width taken from the digest.
- RFC 8037 §A.4 verifies, and is reproduced byte for byte from the private key of §A.1, which Ed25519 being deterministic makes a stronger check than a round trip.
- Project Wycheproof's JSON Web Signature suite, 393 of its 401 cases, and its JSON Web Key suite, all 26. The 39 cases `jose` leaves out for having no ECDSA are run here; the eight that remain outside are recorded, with the reason, in the file that generates them.

Checked against constructed inputs:

- Every vector above is checked again with a bit flipped in the signature, in the payload, and in the header, and refused each time.
- On every Wycheproof case `jose` already runs, `Backend.libcrypto` and `Backend.pure` return the same answer, reason included, case by case. The two share no code below `Jose.Alg`. Where they are known to differ, they are required to differ, so nobody can quietly bring them together: see the note in `Tests.WycheproofKeys`.
- Each of `RS*`, `PS*` and `HS*` signs a token that `Backend.pure` then verifies, so that round trip crosses two implementations. Each of `ES*` signs a pair of coordinates of its curve's width, which verify here, since `Backend.pure` has no ECDSA to return to.
- A key of the wrong kind for an algorithm is refused for the kind, a public key offered as a private one is refused, and bytes that are not a `PrivateKeyInfo` are refused.
- Ten thousand keys are prepared and dropped, and the resident size does not climb, which is what says the `EVP_PKEY` finalizers run.

Not established either way:

- **Nothing about the cryptography here is proved, because all of it is FFI.** What a signature means is decided inside OpenSSL, and no theorem in Lean reaches across that boundary. The vectors and the agreement with `Backend.pure` are the whole of the evidence.
- `Backend.pure` refuses an RSA modulus below 2048 bits, because `leancrypto` does; this backend accepts one, because OpenSSL does and because a shortest acceptable key is policy, which this package does not add. Wycheproof's key case 8 asks for the stricter answer. A caller wanting it must refuse the key before preparing it.
- The refusal that names an algorithm this OpenSSL cannot fetch is written but not exercised: every build tested carries all of them.
- Only one OpenSSL is exercised, whatever the runner and the developer happen to carry. `lean-libcrypto` records which those are.

## Building

`lake build` builds the library; `lake test` runs the suite, which lives in a subproject of its own so that nothing it needs reaches a downstream consumer. `test/tools/Wycheproof.lean` regenerates the vectors from Project Wycheproof's own JSON; it is `jose`'s generator with the list of algorithms to leave out taken from the command line.
