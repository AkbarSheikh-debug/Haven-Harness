# What a run cost

Every headless run and every fleet job reports what it cost: tokens, how much came from the cache, and dollars, split by role and by model. The numbers come from the session's own log, so they are the same for a live run, a resumed one and a log read later.

## In `hn -p --json`

The last line of output is one JSON object. Besides `text`, `end` and `usage` (this turn's own tokens), it has a `cost` object for the whole run, sub-agents included:

```json
{
  "cost": {
    "total":   { "input": 400, "output": 40, "cacheRead": 0, "cacheWrite": 0, "cacheHitRatio": 0, "dollars": 0.0048, "unpriced": [] },
    "byRole":  [ { "role": "main", "input": 300, "output": 30, "cacheRead": 0, "cacheWrite": 0, "cacheHitRatio": 0, "dollars": 0.0036, "unpriced": [] },
                 { "role": "scout", "input": 100, "output": 10, "cacheRead": 0, "cacheWrite": 0, "cacheHitRatio": 0, "dollars": 0.0012, "unpriced": [] } ],
    "byModel": [ { "model": "claude-sonnet-5-5", "input": 400, "output": 40, "cacheRead": 0, "cacheWrite": 0, "cacheHitRatio": 0, "dollars": 0.0048, "unpriced": [] } ],
    "prices":  { "source": "built-in", "checked": null, "models": ["claude-opus-5-5", "claude-sonnet-5-5"] }
  }
}
```

| Field | Meaning |
|---|---|
| `input` | Fresh input tokens, **not** counting cache reads or writes |
| `output` | Output tokens |
| `cacheRead`, `cacheWrite` | Tokens read from and written to the provider's cache |
| `cacheHitRatio` | `cacheRead` divided by everything read in (`input` + `cacheRead` + `cacheWrite`); `null` when nothing was read in |
| `dollars` | The price of those tokens, or **`null`** when any model behind the line has no known price |
| `unpriced` | The models that have no price, so you can see why `dollars` is `null` |
| `role` | `main` is the session you opened; sub-agents appear under the role they were started with (`scout`, `planner`, your own roles). A child that was never recorded under a role is `unknown` |

**Tokens are always exact. Only the money can be unknown, and it is never guessed:** an unpriced model shows `null`, not 0, and one unknown price makes every total it touches `null`.

## In a fleet

Each job's result row has the same `cost` object (`total` and `byRole`) for that job's own session and its sub-agents. A second run that takes a finished job from the results file keeps its cost. After the per-job lines, `hn fleet` prints one line for the whole fleet, for example `Cost: $0.0048, 400 in, 40 out, 0% cached.`

A checker's review session is counted in a job's `tokens`, but not in its `cost`.

## Prices

Built in: the two Claude models listed in `prices.models`. For anything else, give your own prices in `<home>/prices.json` (`~/.hn/prices.json`, or `$HN_HOME/prices.json`), in dollars per million tokens:

```json
{
  "checked": "2026-11-19",
  "prices": {
    "my-model":    { "input": 1, "output": 5, "cacheRead": 0.1, "cacheWrite": 1.25 },
    "qwen3:14b":   { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
  }
}
```

- `checked` is the date you checked the prices. It is required, a file without one is not used, and it is shown in `cost.prices.checked` so a report says how old its prices are.
- All four numbers are required for each model, because a missing one would be a guess. An entry that is not exactly those four numbers, from 0 to 10,000, is refused and named on stderr, and that model stays unpriced.
- Your price wins over a built-in one, model by model.
- A price of zero is a price. A local model run through Ollama costs no API money, so giving it zeros is how you say so; hn never assumes it.
