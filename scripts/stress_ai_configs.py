"""Score the config intake against the AI-style corpus: python scripts/stress_ai_configs.py"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from connectforge.config import schema as spec_mod  # noqa: E402
from fixtures.ai_corpus import CASES  # noqa: E402


def run(verbose=True):
    passed, rows = 0, []
    for name, text, expect, check in CASES:
        t = time.perf_counter()
        try:
            parsed = spec_mod.parse_specs_with_fixes(text) if hasattr(spec_mod, "parse_specs_with_fixes") \
                else (spec_mod.parse_specs(text), [])
            specs, fixes = parsed
            err = None
        except spec_mod.SpecError as e:
            specs, fixes, err = None, [], "; ".join(e.errors)
        except Exception as e:  # anything else is a crash: always a failure
            specs, fixes, err = None, [], f"CRASH {type(e).__name__}: {e}"[:300]
        ms = (time.perf_counter() - t) * 1000
        if expect == "ok":
            ok = specs is not None
            why = err or ""
            if ok and check:
                try:
                    ok = bool(check(specs))
                    why = "" if ok else "accepted, but understood differently than meant"
                except Exception as e:
                    ok, why = False, f"accepted, check failed: {type(e).__name__} {e}"
        else:
            words = expect.split(":", 1)[1]
            ok = specs is None and err is not None and not err.startswith("CRASH") and words.lower() in err.lower()
            why = "accepted (should be refused)" if specs is not None else ("" if ok else f"refused, but message lacks '{words}': {err}")
        passed += ok
        rows.append((ok, name, ms, why, fixes))
    if verbose:
        for ok, name, ms, why, fixes in rows:
            print(f"{'PASS' if ok else 'FAIL'}  {name:45} {ms:7.1f} ms  {why[:150]}")
            for f in fixes if ok else []:
                print(f"        fixed: {f}")
    print(f"\n{passed}/{len(CASES)} handled correctly")
    return passed, len(CASES)


if __name__ == "__main__":
    p, n = run("-q" not in sys.argv)
    sys.exit(0 if p == n else 1)
