import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {cp, mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {promisify} from 'node:util';
import test from 'node:test';

import {sha256} from '../src/evidence.mjs';
import {defaultCorpusRoot, encode, liftCorpus, OUTPUT_PROTOCOL, validateLock} from '../src/lift.mjs';
import {executeExportedTypescript} from '../src/parsers.mjs';
import {executeUseHistoryTrace} from '../src/react-history.mjs';

const run = promisify(execFile);
const ROOT = defaultCorpusRoot();
const TOOL_ROOT = path.resolve(import.meta.dirname, '..');
const CLI = path.join(TOOL_ROOT, 'src/cli.mjs');

async function copiedCorpus(t) {
  const parent = await mkdtemp(path.join(tmpdir(), 'gooir-activity-projection-test-'));
  const root = path.join(parent, 'corpus');
  await cp(ROOT, root, {recursive: true});
  t.after(() => rm(parent, {recursive: true, force: true}));
  return root;
}

test('six product routes corroborate the candidate while three produce concrete projections', async () => {
  const lifted = await liftCorpus();
  assert.equal(lifted.protocol, OUTPUT_PROTOCOL);
  assert.equal(lifted.observations.length, 6);
  assert.equal(new Set(lifted.recurrence.declared_governance_groups).size, 6);
  assert.equal(lifted.recurrence.status, 'three_product_concrete_vertical_with_six_product_static_corroboration');
  assert.deepEqual(lifted.recurrence.contract_vertical.products, ['open_webui', 'chat_ui', 'gemini_cli']);
  assert.equal(lifted.recurrence.contract_vertical.concrete_projection_count, 3);
  assert.ok(lifted.recurrence.rejected.includes('canonical_transcript'));
  assert.ok(lifted.recurrence.rejected.includes('universal_actor_enum'));
  assert.ok(lifted.recurrence.rejected.includes('backing_branch_graph'));
});

test('exact upstream selectors agree on one selected branch and expose malformed divergence', async () => {
  const {behavior} = await liftCorpus();
  const branch = behavior.cases[0];
  const observations = behavior.observations.filter(observation => observation.ordered_source_ids);
  assert.deepEqual(
    observations.map(observation => observation.ordered_source_ids),
    [['s', 'u', 'b'], ['s', 'u', 'b']],
  );
  for (const observation of observations) {
    assert.equal(observation.activity_projection.extent, 'full');
    assert.deepEqual(
      observation.activity_projection.entries.map(entry => entry.source_refs[0].id),
      observation.ordered_source_ids,
    );
    assert.ok(observation.activity_projection.scope_refs.length > 0);
  }
  assert.deepEqual(branch.alternate_selection.open_webui, ['s', 'u', 'a']);
  assert.deepEqual(branch.alternate_selection.chat_ui, ['s', 'u', 'a']);
  assert.deepEqual(branch.malformed_topology.open_webui.result, ['b']);
  assert.equal(branch.malformed_topology.chat_ui.error, 'Ancestor not found');
  assert.equal(branch.malformed_topology.admitted, false);
});

test('exact Gemini useHistory settles a nonchronological projection-local vector under React', async () => {
  const {behavior} = await liftCorpus();
  const trace = behavior.cases[1];
  const observation = behavior.observations.find(candidate => candidate.product_id === 'gemini_cli');
  assert.equal(trace.id, 'react_history_action_trace');
  assert.deepEqual(trace.allocated_ids, [21, 22]);
  assert.deepEqual(trace.settled_history.map(item => item.id), [20, 10, 22]);
  assert.equal(trace.settled_history.some(item => item.id === 21), false);
  assert.equal(trace.settled_history[1].text, 'same-updated');
  assert.deepEqual(observation.ordered_projection_keys, ['20', '10', '22']);
  assert.deepEqual(
    observation.activity_projection.entries.map(entry => entry.projection_key),
    observation.ordered_projection_keys,
  );
  assert.ok(observation.activity_projection.entries.every(entry => entry.source_refs === undefined));
  assert.equal(observation.activity_projection.extent, 'full');
  assert.equal(observation.activity_projection.runtime, 'react@19.2.4');
});

test('React history execution rejects unreviewed source and is bounded by a child timeout', async () => {
  const source = await readFile(path.join(ROOT, 'gemini-cli/history-manager.ts'), 'utf8');
  const start = source.indexOf('export function useHistory');
  const functionSource = source.slice(start).replace(/^export /, '').trimEnd();
  assert.throws(
    () => executeUseHistoryTrace(functionSource.replace('return prevHistory;', 'return [...prevHistory, newItem];'), {}),
    /not the exact review-pinned function node/,
  );
  assert.throws(
    () => executeUseHistoryTrace(functionSource, {initial_history: [], actions: []}, {timeoutMs: 1}),
    /timed out/,
  );

  const sentinel = {ownedBy: 'test-host'};
  const previous = globalThis.IS_REACT_ACT_ENVIRONMENT;
  const hadPrevious = Object.hasOwn(globalThis, 'IS_REACT_ACT_ENVIRONMENT');
  globalThis.IS_REACT_ACT_ENVIRONMENT = sentinel;
  try {
    executeUseHistoryTrace(functionSource, {initial_history: [], actions: []});
    assert.equal(globalThis.IS_REACT_ACT_ENVIRONMENT, sentinel);
  } finally {
    if (hadPrevious) globalThis.IS_REACT_ACT_ENVIRONMENT = previous;
    else delete globalThis.IS_REACT_ACT_ENVIRONMENT;
  }
});

test('isolated execution exposes no host constructor bridge and times every call', () => {
  const probe = executeExportedTypescript(`
    export function probe() {
      let functionEscape = 'blocked';
      try { functionEscape = Function('return process')().versions.node; } catch {}
      return {
        processType: typeof process,
        requireType: typeof require,
        fetchType: typeof fetch,
        moduleConstructorType: typeof module.constructor,
        exportsConstructorType: typeof exports.constructor,
        functionEscape,
      };
    }
  `, 'isolation-probe.ts', 'probe');
  assert.deepEqual(probe(), {
    processType: 'undefined',
    requireType: 'undefined',
    fetchType: 'undefined',
    moduleConstructorType: 'undefined',
    exportsConstructorType: 'undefined',
    functionEscape: 'blocked',
  });

  const spin = executeExportedTypescript('export function spin() { while (true) {} }', 'timeout-probe.ts', 'spin');
  assert.throws(() => spin(), /timed out/);
});

test('all evidence spans select exact nonempty pinned source bytes', async () => {
  const lifted = await liftCorpus();
  const lock = JSON.parse(await readFile(path.join(ROOT, 'authorities.lock.json'), 'utf8'));
  const byId = new Map(lock.authorities.map(entry => [entry.id, entry]));
  for (const observation of lifted.observations) {
    for (const evidence of observation.evidence) {
      const entry = byId.get(evidence.source);
      assert.ok(entry, `unknown evidence source ${evidence.source}`);
      const bytes = await readFile(path.join(ROOT, entry.snapshot_path));
      const {start, end} = evidence.span.utf8_bytes;
      assert.ok(start >= 0 && end > start && end <= bytes.length);
      assert.ok(bytes.subarray(start, end).length > 0);
    }
  }
});

test('a changed native selection path fails closed even when its digest is relocked', async t => {
  const root = await copiedCorpus(t);
  const lockPath = path.join(root, 'authorities.lock.json');
  const lock = JSON.parse(await readFile(lockPath, 'utf8'));
  const authority = lock.authorities.find(entry => entry.id === 'open_web.create_messages_list');
  const filename = path.join(root, authority.snapshot_path);
  const source = await readFile(filename, 'utf8');
  const changed = source.replace('return list.reverse();', 'return list;');
  assert.notEqual(changed, source);
  await writeFile(filename, changed);
  authority.sha256 = sha256(Buffer.from(changed));
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  await assert.rejects(liftCorpus(root), /return list\.reverse\(\)/);
});

test('an executable Svelte change cannot survive through a comment decoy and relock', async t => {
  const root = await copiedCorpus(t);
  const lockPath = path.join(root, 'authorities.lock.json');
  const lock = JSON.parse(await readFile(lockPath, 'utf8'));
  const authority = lock.authorities.find(entry => entry.id === 'open_web.messages_view');
  const filename = path.join(root, authority.snapshot_path);
  const source = await readFile(filename, 'utf8');
  const changed = source.replace('messages = _messages.reverse();', 'messages = _messages; // _messages.reverse()');
  assert.notEqual(changed, source);
  await writeFile(filename, changed);
  authority.sha256 = sha256(Buffer.from(changed));
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  await assert.rejects(liftCorpus(root), /positive evidence differs from its semantic-review pins/);
});

test('a changed Gemini React history transition fails even when its source is relocked', async t => {
  const root = await copiedCorpus(t);
  const lockPath = path.join(root, 'authorities.lock.json');
  const lock = JSON.parse(await readFile(lockPath, 'utf8'));
  const authority = lock.authorities.find(entry => entry.id === 'gemini.history_manager');
  const filename = path.join(root, authority.snapshot_path);
  const source = await readFile(filename, 'utf8');
  const changed = source.replace('return [...prevHistory, newItem];', 'return [newItem, ...prevHistory];');
  assert.notEqual(changed, source);
  await writeFile(filename, changed);
  authority.sha256 = sha256(Buffer.from(changed));
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  await assert.rejects(liftCorpus(root), /return \[\.\.\.prevHistory, newItem\]|positive evidence differs from its semantic-review pins/);
});

test('the provenance lock cannot carry authored semantic verdicts', async t => {
  const root = await copiedCorpus(t);
  const lockPath = path.join(root, 'authorities.lock.json');
  const lock = JSON.parse(await readFile(lockPath, 'utf8'));
  lock.authorities[0].semantic = {transcript: true};
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  await assert.rejects(liftCorpus(root), /prohibited verdict field semantic/);
});

test('snapshot destinations cannot overwrite corpus control state', async () => {
  const lock = JSON.parse(await readFile(path.join(ROOT, 'authorities.lock.json'), 'utf8'));
  lock.authorities[0].snapshot_path = 'observations.lift.json';
  assert.throws(() => validateLock(lock), /snapshot_path is reserved control state/);
});

test('checked-in observations are exact deterministic generator output', async () => {
  const expected = encode(await liftCorpus());
  const actual = await readFile(path.join(ROOT, 'observations.lift.json'), 'utf8');
  assert.equal(actual, expected);
  await run(process.execPath, [CLI, '--check', '--root', ROOT], {cwd: TOOL_ROOT});
});
