# Contributing

The core invariant is simple: **acquisition must not execute target-controlled code**.

Changes that make capture richer are welcome if they preserve that boundary. A dependency parser may read `package.json`; it may not run npm. A repository probe may inspect a workflow file; it may not execute the workflow.

Before proposing a change:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Prefer the Python standard library for acquisition and verification. New dependencies need a concrete reason and should not silently widen the trust boundary.
