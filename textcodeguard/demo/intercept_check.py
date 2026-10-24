import os, sys
from textcodeguard.guard import guarded, GuardBlocked

SAFE = "marker_safe.txt"
UNSAFE = "marker_unsafe.txt"
for f in (SAFE, UNSAFE):
    if os.path.exists(f): os.remove(f)

@guarded
def safe_fn():
    open(SAFE, "w").write("ran")

@guarded
def unsafe_fn():
    # this string is what triggers the block; the body never executes
    os.system("rm -rf /tmp/fake_never_runs")  # noqa
    open(UNSAFE, "w").write("ran")

try:
    safe_fn()
    print("safe_fn ran ->", SAFE, "exists:", os.path.exists(SAFE))
except GuardBlocked as e:
    print("safe_fn BLOCKED (unexpected!)", e)

try:
    unsafe_fn()
    print("unsafe_fn RAN (BAD!)")
except GuardBlocked as e:
    print("unsafe_fn BLOCKED:", e.verdict.categories)

ok = os.path.exists(SAFE) and not os.path.exists(UNSAFE)
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
