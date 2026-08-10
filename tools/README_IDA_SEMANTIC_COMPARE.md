# OG 1.10.163 / AE 1.11.221 IDA semantic comparison

These original MIT-licensed scripts export read-only function evidence from
the two IDA databases and compare the rows paired by
`IDA_Functions_OG_163_and_AE_221.csv`.

Run the examples from the repository root after replacing the three input
paths with the locations of the local CSV and IDA databases.

## Export OG

```powershell
$repo = (Get-Location).Path
$env:CLF4_IDA_SIDE = 'og'
$env:CLF4_SEMANTIC_CSV = 'C:\path\to\IDA_Functions_OG_163_and_AE_221.csv'
$env:CLF4_SEMANTIC_OUT = Join-Path $repo 'build\ida-semantic'
Remove-Item Env:\CLF4_SEMANTIC_LIMIT -ErrorAction SilentlyContinue
& 'C:\Program Files\IDA Professional 9.1\idat.exe' `
  '-A' `
  "-S$(Join-Path $repo 'tools\ida_export_rel_semantics.py')" `
  'C:\path\to\Fallout4-1.10.163.i64'
```

## Export AE 1.11.221

```powershell
$repo = (Get-Location).Path
$env:CLF4_IDA_SIDE = 'ae221'
$env:CLF4_SEMANTIC_CSV = 'C:\path\to\IDA_Functions_OG_163_and_AE_221.csv'
$env:CLF4_SEMANTIC_OUT = Join-Path $repo 'build\ida-semantic'
Remove-Item Env:\CLF4_SEMANTIC_LIMIT -ErrorAction SilentlyContinue
& 'C:\Program Files\IDA Professional 9.1\idat.exe' `
  '-A' `
  "-S$(Join-Path $repo 'tools\ida_export_rel_semantics.py')" `
  'C:\path\to\Fallout4-1.11.221.i64'
```

## Compare and audit current CommonLib IDs

```powershell
python .\tools\compare_rel_semantics.py
python .\tools\audit_commonlib_rel_ids.py
```

Set `CLF4_SEMANTIC_LIMIT` to a small positive number for a smoke test.  The
ClassInformer plugin load warnings printed by the current IDA installation do
not affect these scripts.

The main reports are:

- `rel_semantic_comparison.csv`: all complete CSV ID pairs
- `suspect_matches.csv`: unresolved, review, and suspect pairs
- `member_offset_changes.csv`: changed non-stack displacement evidence
- `current_commonlib_rel_id_audit.csv`: direct IDs used by current sources
- `current_commonlib_unmapped_rel_ids.csv`: remaining IDA work queue
- `current_commonlib_member_offset_changes.csv`: layout evidence used by CommonLib

Similarity scores are triage evidence.  They help find bad mappings and member
offset changes, but do not by themselves prove C++ ABI compatibility.

## Resolve IDs missing from the original CSV

Prepare the current CommonLib target set:

```powershell
python .\tools\prepare_unmapped_rel_targets.py
```

Run `ida_match_unmapped_functions.py` first against OG and then AE.  The AE
pass performs the expensive whole-database semantic candidate scan.  Run
`ida_match_unmapped_functions_context.py` in the same OG-then-AE order to
validate candidates through calls made by confirmed function pairs.

For data and globals, run `ida_match_unmapped_globals_context.py` first against
OG and then AE.  It pairs each concrete data access by instruction signature,
neighboring instructions, and relative position.  This is more reliable than
the coarse `match_unmapped_globals.py` vote report, which is retained as
diagnostic evidence only.

The final conservative working list is generated with:

```powershell
python .\tools\consolidate_ae_relocation_candidates.py
```

Its primary outputs are:

- `proposed_current_commonlib_ae_relocations.csv`: all 224 direct source IDs
- `high_confidence_current_commonlib_ae_relocations.csv`: safe evidence tier
- `proposed_current_commonlib_ae_relocations_summary.txt`: current counts

No runtime Address Library file is generated while medium/review/unresolved
entries remain.  The special MSVC mappings are independently backed by the AE
import and callsites exported by `ida_export_typeinfo_calls.py`.
