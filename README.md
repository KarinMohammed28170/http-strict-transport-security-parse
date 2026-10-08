# hsts-parse

Parse a `Strict-Transport-Security` header into a small policy object: `{ maxAge, includeSubDomains, preload, valid }`. The parser is case-insensitive on directive names, ignores unknown directives, and marks the header invalid only when `max-age` is present but not a non-negative decimal integer.

## Usage

```js
import { parseHsts } from './src/index.js';

const p = parseHsts('max-age=63072000; includeSubDomains; preload');
// p.maxAge              === 63072000
// p.includeSubDomains   === true
// p.preload             === true
// p.valid               === true
```

`parseHsts(headerValue: string)` returns a `PolicyDirective`:

- `maxAge: number | null` — seconds from the `max-age` directive. `null` when absent or malformed.
- `includeSubDomains: boolean` — `true` iff an `includeSubDomains` directive is present (case-insensitive).
- `preload: boolean` — `true` iff a `preload` directive is present (case-insensitive).
- `valid: boolean` — `false` when the input is empty, not a string, or contains a malformed `max-age`.

## Why this exists

HSTS headers are short, but the parsing rules have enough sharp edges (case-insensitivity, optional whitespace, duplicate directives, unknown extensions) that hand-rolling it inline tends to produce subtle security-relevant mistakes — like treating `max-age=-1` as valid, or dropping the policy because a proxy appended an unknown directive. This library makes one defensible interpretation of RFC 6797 §6.1 and exposes it as a single function with no dependencies.

The trade-off: we are **forgiving** rather than strict. Unknown directives are ignored, `includeSubDomains=true` still sets the flag, and a stray `;;` is tolerated. A header is only marked `valid: false` when it is empty or when `max-age` is present but not a non-negative decimal integer. If you want hard rejection of anything non-canonical, this is not the library for it.

## Awkward edges

- **Duplicate `max-age` directives**: the **last** one wins, matching RFC 6797 §6.1. If that last entry is malformed, `maxAge` becomes `null` and `valid` becomes `false` — earlier valid values are discarded.
- **`max-age=+1`** and **`max-age=1e3`** are rejected. The RFC grammar is `1*DIGIT`; a sign prefix or exponent is not a digit.
- **`max-age=00042`** is accepted and parsed as `42`. Leading zeros are permitted by the grammar.
- **Non-string input** returns `{ maxAge: null, includeSubDomains: false, preload: false, valid: false }` rather than throwing.

## Runtime

ESM only. Requires Node 18+ (uses `node:test` and `node:assert/strict`). Run the tests with:

```
node --test
```
