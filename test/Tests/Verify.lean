/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Tests.Driver

/-!
The published vectors `jose` could not run: the two ECDSA appendices of RFC 7515 and the Ed25519
one of RFC 8037. Each is checked for the payload it signed and then three times more with a bit
flipped, in the signature, in the payload and in the header.
-/

public section

namespace Tests.Verify
open Jose Tests.Driver

private structure Vector where
  name : String
  key : String
  token : String
  payload : String

/-- RFC 7515 A.3, ECDSA P-256 with SHA-256, without the `d` that appendix prints beside the key. -/
private def es256 : Vector where
  name := "RFC 7515 A.3 ES256"
  key := "{\"kty\":\"EC\",\"crv\":\"P-256\"," ++
    "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," ++
    "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}"
  token := "eyJhbGciOiJFUzI1NiJ9" ++
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0" ++
    "cnVlfQ" ++
    ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
  payload := "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"

/-- RFC 7515 A.4, ECDSA P-521 with SHA-512. The coordinates are 66 bytes and the digest 64, so this
is the vector that catches a width taken from the digest rather than from the curve. -/
private def es512 : Vector where
  name := "RFC 7515 A.4 ES512"
  key := "{\"kty\":\"EC\",\"crv\":\"P-521\"," ++
    "\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWc" ++
    "eqwQGk\"," ++
    "\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e" ++
    "3kyMj2\"}"
  token := "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA" ++
    ".AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7Xdt" ++
    "AG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
  payload := "Payload"

/-- RFC 8037 §A.4, Ed25519, under the public key of §A.2. -/
private def eddsa : Vector where
  name := "RFC 8037 A.4 EdDSA"
  key := "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"," ++
    "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}"
  token := "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" ++
    ".hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
  payload := "Example of Ed25519 signing"

private def vectors : List Vector := [es256, es512, eddsa]

private def casesFor (vector : Vector) : Array Case :=
  #[{ name := s!"{vector.name} verifies and returns the payload it signed",
      run := do
        let keys ← keysOf [vector.key]
        match ← verify keys vector.token with
        | .error reason => throw <| IO.userError s!"refused: {reason}"
        | .ok payload => expectEq "payload" (String.fromUTF8? payload) (some vector.payload) },
    { name := s!"{vector.name} with a bit flipped in the signature is refused",
      run := do
        let keys ← keysOf [vector.key]
        expectEq "refusal" (refusal (← verify keys (flip vector.token signature)))
          (some .signatureInvalid) },
    { name := s!"{vector.name} with a bit flipped in the payload is refused",
      run := do
        let keys ← keysOf [vector.key]
        expectEq "refusal" (refusal (← verify keys (flip vector.token payload)))
          (some .signatureInvalid) },
    -- Each of these headers carries `alg` and nothing else, so a bit flipped anywhere in one either
    -- breaks the JSON or names another algorithm. What refuses the token is therefore the header
    -- rather than the signature over it, and only the refusal is checked.
    { name := s!"{vector.name} with a bit flipped in the header is refused",
      run := do
        let keys ← keysOf [vector.key]
        expect "refused" (refusal (← verify keys (flip vector.token header))).isSome }]

def cases : Array Case := (vectors.map casesFor).foldl (· ++ ·) #[]

end Tests.Verify
