# The bidama name ledger

Every bidama and level in this repository has a row here. Each row records the collision sweep that cleared the name.

| name | kanji | gloss | swept | verdict | note |
|---|---|---|---|---|---|
| `fuuin` | 封印 | seal — k-of-n threshold signing over the mpc_threshold capability: a group dealt to n shares (`generate`), each share's first round (`offer`: one-use nonces and their commitment), its signature share (`sign`), and the group's ordinary Ed25519 signature from any k of them (`combine`), RFC 9591 FROST over the runtime's `threshold_*` words; a share prints its secret as `foreign` | 2026-10-31 | KEEP | Realized from the provisional verb space `fuuin?` (docs/verbs/names/N1.tsv: swept 0 hits, 0 repos, crates 404). Swept again 2026-10-31 with `rg --no-ignore -w -i 'fuuin\|fūin\|封印'` over the pleme-io root: hits only in blue's own verb graph and its design, which names this space. The space holds the seal verbs still to build (`seal`, `unseal`, `enclose`, `derive`) beside the threshold ones; the threshold words are its first realized rows. |
