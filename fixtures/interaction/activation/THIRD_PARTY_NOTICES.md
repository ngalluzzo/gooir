# Third-party notices

The source snapshots in this directory remain under their upstream licenses.
They are included for research, conformance, and interoperability evidence.

| Project | Upstream | Copyright | License copy |
| --- | --- | --- | --- |
| React | <https://github.com/facebook/react> | Meta Platforms, Inc. and affiliates | `react/LICENSE` |
| Vue | <https://github.com/vuejs/core> | 2018-present, Yuxi (Evan) You and Vue contributors | `vue/LICENSE` |
| Ink | <https://github.com/vadimdemedes/ink> | Vadym Demedes and Sindre Sorhus | `ink/LICENSE` |
| shadcn/ui | <https://github.com/shadcn-ui/ui> | 2023 shadcn | `shadcn/LICENSE.md` |
| Mantine | <https://github.com/mantinedev/mantine> | 2021 Vitaly Rtishchev | `mantine/LICENSE` |

The full commit and per-file digest for every snapshot are recorded in
`authorities.lock.json`. No upstream project supplied a separate root NOTICE
file at the pinned revision.

The React snapshots include `DOMPluginEventSystem.js` from the same pinned
React commit as `SimpleEventPlugin.js`; it supplies the runtime dispatch
executor required to observe the registered `listener(event)` call.

The Ink snapshots include `src/reconciler.ts` from the same pinned Ink commit
as `src/hooks/use-input.ts`; its imports bind the Ink input route to React and
`react-reconciler` for source-derived lineage classification.
