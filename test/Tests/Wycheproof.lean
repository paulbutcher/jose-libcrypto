/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Tests.Driver
public import Wycheproof.Signatures

/-!
Project Wycheproof's JSON Web Signature suite, run against this backend. The vectors are in
`Wycheproof.Signatures`, a package of their own that `jose` publishes and its suite runs too, so
both are answering the same cases rather than two copies of them.

Each case says whether a library should accept the token; what is checked is that this one agrees,
so a case fails both when a forgery is accepted and when a sound token is refused.
-/

public section

namespace Tests.Wycheproof
open Jose Tests.Driver Wycheproof.Signatures

/-- Groups this backend has an answer for. It performs every algorithm `Jose.Alg` names, so the only
ones dropped are those whose key names an algorithm it cannot read, `ES521` being the one the suite
publishes: every case in such a group would be refused for the name rather than for what it was
written to test. A key naming no algorithm is kept, because what those groups test is the key
itself. -/
def answerable (group : Group) : Bool :=
  match group.alg with
  | none => true
  | some name => (Alg.ofString name).isSome

/-- The key set is prepared once per group, as a caller's would be, rather than once per token. -/
def cases : IO (Array Tests.Case) := do
  let mut result : Array Tests.Case := #[]
  for group in groups.filter answerable do
    let keys ← keysOf [group.key]
    let alg := group.alg.getD "no alg"
    for vector in group.cases do
      result := result.push {
        name := s!"wycheproof {group.comment} {alg} {vector.id}",
        run := expectEq "accepted" (← verify keys vector.jws).isOk vector.valid }
  return result

end Tests.Wycheproof
