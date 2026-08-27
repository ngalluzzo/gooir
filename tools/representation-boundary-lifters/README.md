# Representation boundary native lifters

This package inventories syntax that real product sources actually contain. It
does not infer screens, documents, visibility, presentation, user reachability,
or any other semantic boundary from those native facts.

The input lock pins product governance, lifecycle, source bytes, repository
revisions, parser variants, and licenses. The lifter verifies the lock before
using the authoritative Babel and Vue parsers. Its output contains source-bound
imports, exports, JSX constructs, Vue SFC/template constructs, JSON keys, or an
explicitly unparsed HTML record. Unknown or malformed inputs fail closed.
Authority roles are restricted to neutral artifact classes such as manifest,
application source, provider configuration, type/state source, runtime bridge,
materialized source, export, and host source; interpretive UI roles are rejected.

```sh
npm install --prefix tools/representation-boundary-lifters
npm run lift --prefix tools/representation-boundary-lifters -- \
  --lock /absolute/path/to/authorities.lock.json \
  --output /absolute/path/to/native-observations.lift.json

npm run check --prefix tools/representation-boundary-lifters -- \
  --lock /absolute/path/to/authorities.lock.json \
  --output /absolute/path/to/native-observations.lift.json

npm run refresh --prefix tools/representation-boundary-lifters -- \
  --lock /absolute/path/to/authorities.lock.json
```

`--check` regenerates the deterministic projection in memory and requires the
checked-in output to be byte-identical.

`refresh` is the only networked command. It fetches every exact locked commit
into a temporary checkout, verifies each file's SHA-256 before writing its
snapshot, and removes the checkout. `lift` and `check` never fetch.
