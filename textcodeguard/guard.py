import inspect, functools
from textcodeguard.detect.cascade import analyze

class GuardBlocked(Exception):
    def __init__(self, verdict):
        self.verdict = verdict
        super().__init__(f"CodeGuard blocked: {verdict.categories}")

def guard(code: str) -> dict:
    return analyze(code).dict()

def guarded(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            src = inspect.getsource(fn)
        except OSError:
            src = ""
        v = analyze(src)
        if v.verdict == "block":
            raise GuardBlocked(v)
        return fn(*args, **kwargs)
    return wrapper
