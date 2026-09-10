/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Tests.Differential
public import Tests.Memory
public import Tests.Scheme
public import Tests.Sign
public import Tests.Verify
public import Tests.Wycheproof
public import Tests.WycheproofKeys

public def main : IO UInt32 := do
  let cases := Tests.Verify.cases ++ Tests.Sign.cases
    ++ (← Tests.Wycheproof.cases) ++ Tests.WycheproofKeys.cases
    ++ (← Tests.Differential.cases) ++ Tests.Memory.cases
  let failed ← Tests.runCases cases
  IO.println s!"{cases.size - failed} of {cases.size} passed"
  if failed = 0 then return 0 else return 1
