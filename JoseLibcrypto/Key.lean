/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Jose.Backend
public import Libcrypto.Evp.PKey
import Jose.Ecdsa
import Jose.Pure
import JoseLibcrypto.Scheme
import Libcrypto.Evp.Digest
import Libcrypto.Hmac
import Libcrypto.Sign

/-!
A key converted once into what OpenSSL will take it as, and the three operations `Jose.Backend`
names over it.
-/

public section

open Libcrypto

namespace Jose.Libcrypto

def name : String := "libcrypto"

/-- A key converted for this backend. HMAC needs no `EVP_PKEY`, so `oct` keeps the bytes it was
published as; every other kind becomes one, with the kind beside it so that an algorithm offered
the wrong sort of key is refused here rather than inside OpenSSL. -/
inductive PreparedKey where
  | oct (secret : ByteArray)
  | pkey (kind : KeyKind) (key : Evp.PKey)

def PreparedKey.kind : PreparedKey → KeyKind
  | .oct _ => .oct
  | .pkey kind _ => kind

/-- What this OpenSSL must offer to perform the scheme, fetched only to find out whether it does. -/
private def probe : Scheme → IO Unit
  | .hmac d | .pkcs1 d | .pss d _ | .ecdsa _ d => discard <| Evp.Digest.fetch (digest d).name
  | .eddsa _ => discard <| Evp.PKey.generate "ED25519" #[]

/-- An algorithm this build of OpenSSL does not offer, separated from a failure while performing one
it does. The probe runs only after a failure, so the ordinary path never pays for it, and a failure
the probe cannot account for is rethrown rather than reported as a refused token. -/
private def performing {α : Type} (alg : Alg) (act : IO α) : IO (Except Error α) := do
  match ← act.toBaseIO with
  | .ok value => return .ok value
  | .error failure =>
    match ← (probe alg.scheme).toBaseIO with
    | .error _ => return .error (.algUnsupported alg name)
    | .ok _ => throw failure

private def ofSpki (der : ByteArray) (kind : KeyKind) (member : String) :
    IO (Except Error PreparedKey) := do
  match ← Evp.PKey.fromSpki der with
  | none => return .error (.jwkBadMember member)
  | some key => return .ok (.pkey kind key)

/-- The components as `jose` read them, written back into the encoding OpenSSL decodes a public key
from. `jose` has already held each coordinate to the width of its curve, so the point below is the
uncompressed one RFC 5480 §2.2 defines; whether it is on that curve is what `fromSpki` answers. -/
def prepare (jwk : Jwk) : IO (Except Error PreparedKey) := do
  match jwk.material with
  | .oct secret => return .ok (.oct secret)
  | .rsa modulus exponent =>
    ofSpki (Leancrypto.Der.rsaPublicKeyInfo { modulus := modulus, exponent := exponent }) .rsa "n"
  | .ec crv x y =>
    ofSpki (Leancrypto.Der.ecPublicKeyInfo (curveOid crv) (⟨#[0x04]⟩ ++ x ++ y)) .ec "x"
  -- Ed25519 is the one algorithm here an OpenSSL build plausibly lacks, and an OKP key is for no
  -- other, so a failure to build one can be reported as the algorithm rather than only thrown.
  -- No such algorithm can be named for an RSA or an EC key, which six and three of them share.
  | .okp _ x =>
    match ← performing .eddsa (Evp.PKey.fromRawPublicKey "ED25519" x) with
    | .error reason => return .error reason
    | .ok none => return .error (.jwkBadMember "x")
    | .ok (some key) => return .ok (.pkey .okp key)

/-- One signature, checked. A signature that is not the width its curve requires is `false` rather
than an error: it is a signature nobody could have produced over these bytes, which is the same
answer OpenSSL gives for one that is the right width and still wrong. -/
def verifySignature (alg : Alg) (key : PreparedKey) (signingInput signature : ByteArray) :
    IO (Except Error Bool) := do
  match alg.scheme, key with
  -- RFC 7518 §3.2 is `jose`'s rule rather than this backend's, so it is read from where that
  -- backend states it. Restating it here is how the two come to disagree about the same key.
  | .hmac d, .oct secret =>
    match Pure.secretLongEnough d secret with
    | .error reason => return .error reason
    | .ok () => performing alg (Hmac.verify (digest d) secret signingInput signature)
  | .pkcs1 d, .pkey .rsa key =>
    performing alg (Sign.verify (.rsaPkcs1 (digest d)) key signingInput signature)
  | .pss d _, .pkey .rsa key =>
    performing alg (Sign.verify (.rsaPss (digest d) .digest) key signingInput signature)
  | .ecdsa crv d, .pkey .ec key =>
    match Ecdsa.toDer crv signature with
    | none => return .ok false
    | some der => performing alg (Sign.verify (.ecdsa (digest d)) key signingInput der)
  | .eddsa _, .pkey .okp key => performing alg (Sign.verify .ed25519 key signingInput signature)
  | _, key => return .error (.keyKindMismatch alg key.kind)

/-- A signature over the signing input. An ECDSA signature leaves as the `R‖S` of RFC 7518 §3.4,
exactly inverting what `verifySignature` does to one arriving. -/
def signature (alg : Alg) (key : PreparedKey) (signingInput : ByteArray) :
    IO (Except Error ByteArray) := do
  match alg.scheme, key with
  | .hmac d, .oct secret =>
    match Pure.secretLongEnough d secret with
    | .error reason => return .error reason
    | .ok () => performing alg (Hmac.compute (digest d) secret signingInput)
  | .pkcs1 d, .pkey .rsa key => performing alg (Sign.sign (.rsaPkcs1 (digest d)) key signingInput)
  | .pss d _, .pkey .rsa key =>
    performing alg (Sign.sign (.rsaPss (digest d) .digest) key signingInput)
  | .ecdsa crv d, .pkey .ec key =>
    match ← performing alg (Sign.sign (.ecdsa (digest d)) key signingInput) with
    | .error reason => return .error reason
    | .ok der =>
      match Ecdsa.ofDer crv der with
      | some raw => return .ok raw
      | none =>
        -- Only a key on another curve reaches this: OpenSSL wrote a well formed signature, and it
        -- is not a pair of coordinates this curve could hold.
        throw <| IO.userError s!"{alg.name} needs a key on {crv.name}, and this key is on \
          another curve"
  | .eddsa _, .pkey .okp key => performing alg (Sign.sign .ed25519 key signingInput)
  | _, key => return .error (.keyKindMismatch alg key.kind)

/-- `RSA-PSS` is an RSA key restricted to one scheme, which JOSE has no separate kind for. -/
private def kindOfTypeName : String → Option KeyKind
  | "RSA" | "RSA-PSS" => some .rsa
  | "EC" => some .ec
  | "ED25519" => some .okp
  | _ => none

private def ofDecoded (key : Option Evp.PKey) : Except Error PreparedKey :=
  match key with
  | none => .error (.jwkBadMember "d")
  | some key =>
    match kindOfTypeName key.typeName with
    | none => .error (.jwkUnknownKeyType key.typeName)
    | some kind => .ok (.pkey kind key)

/-- A private key, which a JWK never carries: `jose` refuses one that does, so a signing key comes
from a file. This is outside the `Backend` record for that reason, and `Jose.Jws.token` takes what
it returns without either package changing.

Bytes that are not a `PrivateKeyInfo`, an `EncryptedPrivateKeyInfo` among them since
`lean-libcrypto` binds no passphrase callback, are refused as `jwkBadMember` naming `d`. `jose`
has no error for a key file that will not decode, and `d` is what RFC 7518 §6 calls the component
that did not. -/
def PreparedKey.ofPkcs8 (der : ByteArray) : IO (Except Error PreparedKey) :=
  return ofDecoded (← Evp.PKey.fromPkcs8 der)

/-- The same key as PEM, which is the armour `-----BEGIN PRIVATE KEY-----` encloses. -/
def PreparedKey.ofPem (pem : String) : IO (Except Error PreparedKey) :=
  return ofDecoded (← Evp.PKey.decode pem.toUTF8 .privateKey "PEM" "PrivateKeyInfo")

end Libcrypto

/-- The backend this package exists to supply, chosen exactly as `Backend.pure` is. -/
@[expose] def Backend.libcrypto : Backend where
  PreparedKey := Libcrypto.PreparedKey
  prepare := Libcrypto.prepare
  verify := Libcrypto.verifySignature
  sign := Libcrypto.signature

end Jose
