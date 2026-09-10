/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Tests.Driver
public import Tests.WycheproofVectors

/-!
Project Wycheproof's JSON Web Signature suite, run against this backend, including the `ES*` groups
`jose`'s own suite leaves out because the backend it ships cannot perform them.

Each case says whether a library should accept the token; what is checked is that this one agrees,
so a case fails both when a forgery is accepted and when a sound token is refused.
-/

public section

namespace Tests.Wycheproof
open Jose Tests.Driver

/-- The key set is prepared once per group, as a caller's would be, rather than once per token. -/
def cases : IO (Array Tests.Case) := do
  let mut result : Array Tests.Case := #[]
  for group in groups do
    let keys ← keysOf [group.key]
    for vector in group.cases do
      result := result.push {
        name := s!"wycheproof {group.comment} {group.alg} {vector.id}",
        run := expectEq "accepted" (← verify keys vector.jws).isOk vector.valid }
  return result

end Tests.Wycheproof
