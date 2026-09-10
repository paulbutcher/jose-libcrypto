/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import JoseLibcrypto
public import Leancrypto.Codec.Base64Url
public import Tests.Harness

/-!
What the checks below share: a key set prepared for this backend, a policy as wide as the backend,
and the tampering that turns a published vector into the negative case beside it.
-/

public section

namespace Tests.Driver
open Jose

/-- Every algorithm this backend performs, which is every algorithm `Jose.Alg` names. A vector is
then refused by the check it was written to exercise rather than by a policy this suite pinned. -/
def algs : Array Alg :=
  #[.hs256, .hs384, .hs512, .rs256, .rs384, .rs512, .ps256, .ps384, .ps512,
    .es256, .es384, .es512, .eddsa]

def policy : Policy :=
  (Policy.mk? algs "joe" #["everyone"]).getD
    { algs := #[.hs256], issuer := "joe", audience := #["everyone"] }

def empty : KeySet Jose.Backend.libcrypto := { keys := #[], skipped := #[] }

/-- A key this library will not read, or one OpenSSL will not accept, leaves the set empty rather
than failing the check outright. Every token is then refused for having no key to try, which is the
answer the groups publishing such a key are asking about. -/
def keySet (document : String) : IO (KeySet Jose.Backend.libcrypto) := do
  match Jwks.parse {} document with
  | .error _ => return empty
  | .ok set =>
    match ← KeySet.ofJwks Jose.Backend.libcrypto set with
    | .error _ => return empty
    | .ok prepared => return prepared

def keysOf (keys : List String) : IO (KeySet Jose.Backend.libcrypto) :=
  keySet ("{\"keys\":[" ++ String.intercalate "," keys ++ "]}")

def verify (keys : KeySet Jose.Backend.libcrypto) (token : String) : IO (Except Error ByteArray) :=
  Jws.verify Jose.Backend.libcrypto policy keys token

/-- One bit of the decoded part, flipped, and the part written back out. Flipping a base64url
character instead would risk changing nothing, since several characters encode the same bits at the
end of a part. -/
def tamper (text : String) : String :=
  match Leancrypto.Codec.Base64Url.decodeString text with
  | none => text
  | some bytes => Leancrypto.Codec.Base64Url.encodeString ⟨bytes.data.modify 0 (· ^^^ 1)⟩

/-- The token with one bit flipped in the part at `part`, counting from the header. -/
def flip (token : String) (part : Nat) : String :=
  String.intercalate "."
    ((token.splitOn ".").mapIdx fun index text => if index == part then tamper text else text)

def header : Nat := 0
def payload : Nat := 1
def signature : Nat := 2

def refusal {α : Type} (result : Except Error α) : Option Error :=
  match result with
  | .error reason => some reason
  | .ok _ => none

end Tests.Driver
