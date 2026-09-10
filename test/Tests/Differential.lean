/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Tests.Driver
public import Tests.WycheproofKeys
public import Wycheproof.Keys
public import Wycheproof.Signatures

/-!
Every Wycheproof case `jose` already runs, put to both backends and required to come back the same.
Neither is compared with the suite's own answer here, which the two files above do; what this adds
is that implementations sharing no code below `Jose.Alg` agree case by case, so a disagreement names
which of them to look at. Both suites read the same vector package, so "the cases `jose` runs" is
the same list here as there rather than a copy of it that could drift.

A set holding an elliptic curve key is left out, because `Backend.pure` refuses every algorithm
such a key is for, which is the one place the two are meant to differ by design.
`Tests.WycheproofKeys.divergences` is the one place they differ in fact, and is required to differ
here rather than excused.
-/

public section

namespace Tests.Differential
open Jose

/-- Whether `Backend.pure` can use every key in the set, which is what makes its answer one to
compare rather than a refusal by algorithm. -/
private def sharedWithPure (keys : KeySet Jose.Backend.pure) : Bool :=
  keys.keys.all fun prepared =>
    prepared.jwk.material.kind == .oct || prepared.jwk.material.kind == .rsa

private def pureKeys (document : String) : KeySet Jose.Backend.pure :=
  match Jwks.parse {} document with
  | .ok set => Pure.keySet set
  | .error _ => Pure.keySet Jwks.empty

/-- The whole answer, not merely whether the token was accepted: two backends refusing the same
token for different reasons have not agreed, because the reason is what a caller acts on. -/
private def same (native lean : Except Error ByteArray) : Bool :=
  match native, lean with
  | .ok left, .ok right => left.toList == right.toList
  | .error left, .error right => left == right
  | _, _ => false

private def report {α : Type} (result : Except Error α) : String :=
  match result with
  | .ok _ => "accepted"
  | .error reason => s!"refused ({reason})"

private def check (agreeing : Bool) (native lean : Except Error ByteArray) : IO Unit :=
  unless same native lean == agreeing do
    throw <| IO.userError <|
      if agreeing then s!"libcrypto {report native}, pure {report lean}"
      else s!"both {report native}, and this case is recorded as one where they differ"

def cases : IO (Array Tests.Case) := do
  let mut result : Array Tests.Case := #[]
  for group in Wycheproof.Signatures.groups do
    let document := "{\"keys\":[" ++ group.key ++ "]}"
    let lean := pureKeys document
    if sharedWithPure lean then
      let native ← Tests.Driver.keySet document
      let alg := group.alg.getD "no alg"
      for vector in group.cases do
        result := result.push {
          name := s!"agreement {group.comment} {alg} {vector.id}",
          run := check true (← Tests.Driver.verify native vector.jws)
            (Pure.verify Tests.Driver.policy lean vector.jws) }
  for group in Wycheproof.Keys.groups do
    let lean := pureKeys group.keys
    if sharedWithPure lean then
      let native ← Tests.Driver.keySet group.keys
      for vector in group.cases do
        let agreeing := !Tests.WycheproofKeys.divergences.contains vector.id
        result := result.push {
          name := s!"agreement key {group.comment} {vector.id}",
          run := check agreeing (← Tests.Driver.verify native vector.jws)
            (Pure.verify Tests.Driver.policy lean vector.jws) }
  return result

end Tests.Differential
