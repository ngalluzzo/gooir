# Production representation-boundary corpus

This corpus pins native source from six current production products and one
historical production corroborator. It exists to test whether `screen`,
`document`, or another representation boundary is actually shared by React
web, Vue web, and Ink terminal products.

The lock is provenance-only. Its roles name upstream-native source positions;
they are not semantic verdicts. The generated observation document contains a
parser-backed inventory of native syntax and likewise does not claim that a
component is visible, accessible, a screen, a document, or semantically
equivalent to a component in another product.

The products are independent on the product-meaning axis. They are not all
independent on the runtime-realization axis: Gemini CLI, Shopify CLI, and the
historical TypeScript Codex CLI all derive through React and Ink. Different
applications or dependency versions do not create independent renderer votes.

Run the lifter from the repository root:

```sh
npm ci --prefix tools/representation-boundary-lifters
npm test --prefix tools/representation-boundary-lifters
npm run lift --prefix tools/representation-boundary-lifters -- \
  --lock "$PWD/fixtures/representation/boundaries/authorities.lock.json" \
  --output "$PWD/fixtures/representation/boundaries/native-observations.lift.json"
npm run check --prefix tools/representation-boundary-lifters -- \
  --lock "$PWD/fixtures/representation/boundaries/authorities.lock.json" \
  --output "$PWD/fixtures/representation/boundaries/native-observations.lift.json"
```

The checked-in sources are exact upstream bytes at the commits in
`authorities.lock.json`. They are redistributed under the corresponding
license snapshot and summarized in `THIRD_PARTY_NOTICES.md`.
