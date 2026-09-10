/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Tests.Driver

/-!
Signing. Ed25519 is deterministic, so its published signature is reproduced byte for byte; the rest
are not, so what is checked is that a signature made here verifies and that one bit of it flipped
does not.

An RSA or HMAC signature goes back to `Backend.pure`, which shares no code with this one below
`Jose.Alg`, so that round trip crosses two implementations rather than returning to the one that
made it. ECDSA has no such verifier to go back to, and comes back here.
-/

public section

namespace Tests.Sign
open Jose Leancrypto Tests.Driver

/-- RFC 8037 §A.1's `d` as the `PrivateKeyInfo` OpenSSL decodes: the version, the Ed25519
identifier `1.3.101.112`, and the seed inside the `OCTET STRING` that the outer one carries. -/
private def ed25519Pkcs8 (seed : ByteArray) : ByteArray :=
  let octetString := Der.tlv 0x04
  Der.sequence (Der.integer 0 ++ Der.sequence (Der.objectIdentifier ⟨#[0x2b, 0x65, 0x70]⟩) ++
    octetString (octetString seed))

private def decode (text : String) : ByteArray :=
  (Codec.Base64Url.decodeString text).getD ⟨#[]⟩

private def ed25519Seed : String := "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"

private def ed25519Header : String := "{\"alg\":\"EdDSA\"}"

private def message : String := "Example of Ed25519 signing"

private def ed25519Token : String :=
  "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" ++
  ".hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"

private def signingKey (der : ByteArray) : IO Jose.Libcrypto.PreparedKey := do
  match ← Jose.Libcrypto.PreparedKey.ofPkcs8 der with
  | .error reason => throw <| IO.userError s!"the key was refused: {reason}"
  | .ok key => return key

private def sign (alg : Alg) (key : Jose.Libcrypto.PreparedKey) (payload : String) :
    IO String := do
  let header := "{\"alg\":\"" ++ alg.name ++ "\"}"
  match ← Jws.token Jose.Backend.libcrypto alg key header payload with
  | .error reason => throw <| IO.userError s!"signing was refused: {reason}"
  | .ok token => return token

/-- The `BIT STRING` a `SubjectPublicKeyInfo` ends with, which for an elliptic curve key is the
uncompressed `0x04 ‖ X ‖ Y` and for Ed25519 the key itself. The algorithm identifier is passed
over rather than read: which key this is is already known, since it is the key generated here. -/
private def keyOfSpki (spki : ByteArray) : Option ByteArray := do
  let info ← Der.readTagged Der.sequenceTag spki spki.size 0
  let algorithm ← Der.readTagged Der.sequenceTag spki info.next info.start
  let (start, stop) ← Der.readBitString spki info.next algorithm.next
  guard (stop = info.next)
  some (spki.extract start stop)

private def jwkOf (material : KeyMaterial) : Jwk :=
  { material := material, kid := none, alg := none }

private def ecJwk (crv : Crv) (spki : ByteArray) : IO Jwk := do
  let some point := keyOfSpki spki | throw <| IO.userError "the key carries no point"
  let width := crv.coordinateSize
  if point.size != 2 * width + 1 then
    throw <| IO.userError s!"the point is {point.size} bytes, not {2 * width + 1}"
  let x := point.extract 1 (width + 1)
  let y := point.extract (width + 1) point.size
  return jwkOf (.ec crv x y)

private def okpJwk (spki : ByteArray) : IO Jwk := do
  let some key := keyOfSpki spki | throw <| IO.userError "the key carries no public value"
  return jwkOf (.okp .ed25519 key)

private def rsaJwk (spki : ByteArray) : IO Jwk := do
  let some key := Der.publicKeyOfSpki spki | throw <| IO.userError "the key is not an RSA key"
  return jwkOf (.rsa key.modulus key.exponent)

/-- A signature made here, put to `Backend.pure`, and then the same token with one bit of its
signature flipped, which must not verify. -/
private def throughPure (jwk : Jwk) (token : String) : IO Unit := do
  let keys := Pure.keySet (Jwks.ofKeys #[jwk])
  match Pure.verify policy keys token with
  | .error reason => throw <| IO.userError s!"the pure backend refused it: {reason}"
  | .ok _ =>
    expectEq "a flipped bit verified" (Pure.verify policy keys (flip token signature)).isOk false

private def throughThis (jwk : Jwk) (token : String) : IO Unit := do
  match ← KeySet.ofJwks Jose.Backend.libcrypto (Jwks.ofKeys #[jwk]) with
  | .error reason => throw <| IO.userError s!"the key was refused: {reason}"
  | .ok keys =>
    match ← verify keys token with
    | .error reason => throw <| IO.userError s!"this backend refused it: {reason}"
    | .ok _ => expectEq "a flipped bit verified" (← verify keys (flip token signature)).isOk false

private def curves : List (Crv × Alg × String) :=
  [(.p256, .es256, "P-256"), (.p384, .es384, "P-384"), (.p521, .es512, "P-521")]

private def rsaAlgs : List Alg := [.rs256, .rs384, .rs512, .ps256, .ps384, .ps512]

private def hmacAlgs : List Alg := [.hs256, .hs384, .hs512]

private def published : Array Tests.Case :=
  #[{ name := "RFC 8037 A.4 is reproduced byte for byte from its private key",
      run := do
        let key ← signingKey (ed25519Pkcs8 (decode ed25519Seed))
        expectEq "token" (← sign .eddsa key message) ed25519Token },
    { name := "a payload one character longer signs to a different token",
      run := do
        let key ← signingKey (ed25519Pkcs8 (decode ed25519Seed))
        let other ← sign .eddsa key (message ++ "!")
        expect "the signature did not change" (other != ed25519Token) },
    { name := "EdDSA signs with a PEM key, and what it signed verifies",
      run := do
        let generated ← Libcrypto.Evp.PKey.generate "ED25519" #[]
        let some text := String.fromUTF8? (← generated.encode .privateKey "PEM" "PrivateKeyInfo")
          | throw <| IO.userError "the PEM is not text"
        match ← Jose.Libcrypto.PreparedKey.ofPem text with
        | .error reason => throw <| IO.userError s!"the PEM was refused: {reason}"
        | .ok key =>
          throughThis (← okpJwk (← generated.toSpki)) (← sign .eddsa key message) },
    { name := "a public key offered as a private one is refused",
      run := do
        let generated ← Libcrypto.Evp.PKey.generate "ED25519" #[]
        expect "it decoded" !(← Jose.Libcrypto.PreparedKey.ofPkcs8 (← generated.toSpki)).isOk },
    { name := "bytes that are not a PrivateKeyInfo are refused",
      run := do
        expect "it decoded" !(← Jose.Libcrypto.PreparedKey.ofPkcs8 ⟨#[0x30, 0x00]⟩).isOk },
    { name := "an algorithm is refused a key of another kind",
      run := do
        let generated ← Libcrypto.Evp.PKey.generate "ED25519" #[]
        let key ← signingKey (← generated.toPkcs8)
        expectEq "refusal" (refusal (← Jose.Backend.libcrypto.sign .es256 key message.toUTF8))
          (some (.keyKindMismatch .es256 .okp)) }]

def cases : Array Tests.Case :=
  published
    ++ (rsaAlgs.map fun alg =>
      { name := s!"{alg.name} signs, and the pure backend verifies what it signed",
        run := do
          let generated ← Libcrypto.Evp.PKey.generate "RSA" #[⟨"bits", .uint 2048⟩]
          let token ← sign alg (← signingKey (← generated.toPkcs8)) message
          throughPure (← rsaJwk (← generated.toSpki)) token }).toArray
    ++ (curves.map fun (crv, alg, group) =>
      { name := s!"{alg.name} signs a pair of {crv.name} coordinates, which verify here",
        run := do
          let generated ← Libcrypto.Evp.PKey.generate "EC" #[⟨"group", .utf8 group⟩]
          let token ← sign alg (← signingKey (← generated.toPkcs8)) message
          let some raw := Codec.Base64Url.decodeString ((token.splitOn ".").getD 2 "")
            | throw <| IO.userError "the signature is not base64url"
          expectEq "signature width" raw.size (2 * crv.coordinateSize)
          throughThis (← ecJwk crv (← generated.toSpki)) token }).toArray
    ++ (hmacAlgs.map fun alg =>
      { name := s!"{alg.name} signs, and the pure backend verifies what it signed",
        run := do
          let secret : ByteArray := ⟨Array.replicate 64 0x2b⟩
          throughPure (jwkOf (.oct secret)) (← sign alg (.oct secret) message) }).toArray

end Tests.Sign
