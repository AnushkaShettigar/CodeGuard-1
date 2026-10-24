"""Pasteable CodeGuard samples and helpers.

* ``samples.jsonl``          - full records (code + security intent + measured verdicts)
* ``check_requests.jsonl``   - bare ``{"code": ...}`` objects, ready to POST
* ``SAMPLES.md``             - human-readable table of every sample and its result
* ``verify_samples.py``      - regenerates the three files above from verified runs
* ``run_samples.py``         - runs the samples in-process or against a live service
"""
