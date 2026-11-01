"""Mutation fuzzing of the config intake: python scripts/fuzz_intake.py [iterations]

Every input must end in an accepted config or a SpecError with a message; anything else is a crash."""

import random
import sys
import time
import traceback
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from connectforge.config.intake import corrected_yaml  # noqa: E402
from connectforge.config.schema import SpecError, parse_specs_with_fixes  # noqa: E402
from fixtures.ai_corpus import CASES  # noqa: E402

JUNK = ["{", "}", "[", "]", ":", "- ", "&a", "*a", "!!str", "~", "null", "true", "0", "-1", "1e309", "'", '"', "\t",
        "${secret:}", "{{ }}", "$..", "[*]", "\x00", "é", "🔥", "?", "|", ">", "---", "...", "%YAML 1.2"]


def mutate(text: str, rnd: random.Random) -> str:
    lines = text.splitlines()
    for _ in range(rnd.randint(1, 4)):
        op = rnd.randrange(7)
        if not lines:
            lines = [""]
        i = rnd.randrange(len(lines))
        if op == 0:
            del lines[i]
        elif op == 1:
            lines.insert(i, lines[rnd.randrange(len(lines))])
        elif op == 2 and lines[i]:
            j = rnd.randrange(len(lines[i]))
            lines[i] = lines[i][:j] + rnd.choice(JUNK) + lines[i][j:]
        elif op == 3:
            lines[i] = "  " + lines[i]
        elif op == 4:
            lines[i] = lines[i].lstrip()
        elif op == 5 and ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            lines[i] = f"{k}: {rnd.choice(['', '[]', '{}', '42', 'null', 'yes', '[a, b]', '{x: 1}', v * 2])}"
        else:
            rnd.shuffle(lines)
    return "\n".join(lines)


def main(n: int) -> int:
    rnd = random.Random(1234)
    texts = [c[1] for c in CASES if len(c[1]) < 50_000]
    outcomes, crashes, slow = Counter(), [], []
    started = time.perf_counter()
    for _ in range(n):
        text = mutate(rnd.choice(texts), rnd)
        t = time.perf_counter()
        try:
            specs, _ = parse_specs_with_fixes(text)
            outcomes["accepted"] += 1
            corrected_yaml(text)
        except SpecError as e:
            outcomes["refused"] += 1
            if not all(isinstance(m, str) and m for m in e.errors):
                crashes.append((text, "SpecError without a message"))
        except Exception as e:  # noqa: BLE001 - this is what we are hunting
            crashes.append((text, "".join(traceback.format_exception_only(type(e), e)).strip()))
        ms = (time.perf_counter() - t) * 1000
        if ms > 200:
            slow.append((ms, text[:80]))
    took = time.perf_counter() - started
    print(f"{n} mutated files in {took:.1f}s ({n / took:.0f}/s): {dict(outcomes)}; crashes: {len(crashes)}; "
          f"slower than 200 ms: {len(slow)}")
    for text, err in crashes[:8]:
        print("CRASH:", err.splitlines()[-1][:200], "\n  input:", repr(text[:200]))
    # corrected YAML must be stable: reading it back needs no further fixes
    unstable = 0
    for name, text, expect, _ in CASES:
        if expect == "ok":
            again = parse_specs_with_fixes(corrected_yaml(text))[1]
            if again:
                unstable += 1
                print("UNSTABLE corrected YAML:", name, again[:3])
    print(f"corrected YAML stable for every accepted corpus case: {unstable == 0}")
    return 1 if crashes or unstable else 0


if __name__ == "__main__":
    sys.exit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 20000))
