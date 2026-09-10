/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Tests.Driver

/-!
Every prepared key holds an `EVP_PKEY` that only a finalizer releases. A key set is prepared once
per rotation and dropped, so a finalizer that never ran would show as a process that grows for as
long as it keeps fetching keys.
-/

public section

namespace Tests.Memory
open Jose Tests.Driver

/-- Resident size in bytes. Only Linux is covered; elsewhere there is nothing portable to read, and
the caller says it skipped rather than guessing. -/
private def residentBytes : IO (Option Nat) := do
  let statm : System.FilePath := "/proc/self/statm"
  if !(← statm.pathExists) then return none
  let some pages := ((← IO.FS.readFile statm).splitOn " ")[1]?.bind (·.trimAscii.toString.toNat?)
    | return none
  let pageSize ← IO.Process.run { cmd := "getconf", args := #["PAGESIZE"] }
  return (pageSize.trimAscii.toString.toNat?).map (pages * ·)

/-- Runs `round` once to pay for whatever one-off growth the allocators do, then again with the
resident size read either side. A finalizer that never runs shows up as growth far beyond
`allowance`; ordinary allocator behaviour does not show up at all, because what the first round
used is reused by the second. -/
private def expectNoGrowth (allowance : Nat) (round : IO Unit) : IO Unit := do
  round
  match ← residentBytes with
  | none => IO.print "(skipped: resident size is unavailable here) "
  | some before =>
    round
    let some after ← residentBytes
      | throw <| IO.userError "resident size became unreadable mid-test"
    expect s!"resident size grew by {after - before} bytes, allowing {allowance}"
      (after ≤ before + allowance)

private def keys : String :=
  "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\"," ++
  "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," ++
  "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}]}"

def cases : Array Tests.Case :=
  #[{ name := "preparing and dropping ten thousand keys does not grow the process",
      run := expectNoGrowth (8 * 1024 * 1024) do
        for _ in [0:10000] do
          let prepared ← keySet keys
          expect "the key set came back empty" (prepared.keys.size == 1) }]

end Tests.Memory
