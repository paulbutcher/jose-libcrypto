/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Tests.Driver
public import Tests.WycheproofKeyVectors

/-!
Project Wycheproof's JSON Web Key suite. Each case is a key set and a token, and what it asks is
whether reading that set and checking that token should succeed. A set this library refuses outright
and one it reads but finds no usable key in are the same answer here, which is what the suite is
asking about.
-/

public section

namespace Tests.WycheproofKeys
open Jose Tests.Driver

/-- Where this backend answers against the suite, on purpose. `leancrypto` refuses an RSA modulus
below 2048 bits, which is what makes `Backend.pure` reject case 8; OpenSSL has no such minimum, and
a shortest acceptable key is policy, which belongs to whoever admits keys rather than to a backend
that adds none. Checked as an acceptance rather than dropped, so that anyone adding a minimum here
has to come and read this. -/
def divergences : List Nat := [8]

def cases : Array Tests.Case :=
  groups.foldl (init := #[]) fun result group =>
    group.cases.foldl (init := result) fun result vector =>
      let diverges := divergences.contains vector.id
      result.push {
        name := s!"wycheproof key {group.comment} {vector.id}" ++
          if diverges then " answers against the suite" else "",
        run := do
          let keys ← keySet group.keys
          expectEq "accepted" (← verify keys vector.jws).isOk (vector.valid != diverges) }

end Tests.WycheproofKeys
