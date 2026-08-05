## Summary

<!-- What this change does and why. Keep it focused — one PR, one issue. -->

## Related issue

Fixes #N

<!-- Link the exact issue this PR resolves. One PR should resolve exactly one issue. -->

## Tests

<!-- List what you ran and the results. -->

- [ ] `pytest` — full suite passes
- [ ] Manual run: `stellargate run --config stellargate.yaml --json-report report.json`

Results:

```
<paste output here>
```

## Impact on stable contracts

<!-- These are intentionally stable contracts. Flag any change to them explicitly. -->

- Exit code semantics (`0` pass / `1` fail): unchanged / changed
- `--config` YAML structure: unchanged / changed
- Report format (JSON / Markdown): unchanged / changed

## Checklist

- [ ] Change is small and scoped to the issue above
- [ ] No unrelated refactoring bundled in
- [ ] No real secrets or sensitive data committed
