/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module


public section

namespace Tests

/-- A named check. Failure is signalled by throwing, so a check reads as straight-line `IO` rather
than threading a result through. -/
structure Case where
  name : String
  run : IO Unit

def expect (what : String) (ok : Bool) : IO Unit :=
  unless ok do throw <| IO.userError what

def expectEq {α : Type} [BEq α] [ToString α] (what : String) (actual expected : α) : IO Unit :=
  unless actual == expected do
    throw <| IO.userError s!"{what}: expected {expected}, got {actual}"

/-- Runs every case, reporting each, and returns the number that failed. The name is flushed before
the case runs, so a case that takes the process down rather than throwing still leaves its name as
the last thing in the log. -/
def runCases (cases : Array Case) : IO Nat := do
  let stdout ← IO.getStdout
  let mut failed := 0
  for case in cases do
    stdout.putStr s!"{case.name} ... "
    stdout.flush
    match ← case.run.toBaseIO with
    | .ok _ => stdout.putStrLn "ok"
    | .error e =>
      failed := failed + 1
      stdout.putStrLn s!"FAILED: {e}"
    stdout.flush
  return failed

end Tests
