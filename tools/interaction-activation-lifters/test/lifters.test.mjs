import assert from 'node:assert/strict';
import {mkdtemp, cp, readFile, rm, writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {allNodes, parseAuthority} from '../src/ast.mjs';
import {
  defaultCorpusRoot,
  encodeProjection,
  liftCorpus,
  sha256,
} from '../src/lift.mjs';

test('three source-specific lifters establish only the callable handler outcome', async () => {
  const projection = await liftCorpus();
  assert.deepEqual(
    projection.observations.map(observation => ({
      subject: observation.audit_subject_id,
      group: observation.authority_group,
      ecosystem: observation.ecosystem,
      lineage: `${observation.lineage.runtime}/${observation.lineage.participation}`,
      outcome: observation.semantic.outcome,
    })),
    [
      {
        subject: 'react-dom:SimpleEventPlugin/onClick',
        group: 'react_dom',
        ecosystem: 'react_dom',
        lineage: 'react/authority',
        outcome: 'invokes_registered_handler',
      },
      {
        subject: 'vue-runtime-dom:patchEvent/onClick',
        group: 'vue_runtime_dom',
        ecosystem: 'vue_runtime_dom',
        lineage: 'vue/authority',
        outcome: 'invokes_registered_handler',
      },
      {
        subject: 'ink:useInput/input',
        group: 'ink_terminal',
        ecosystem: 'ink',
        lineage: 'react/renderer',
        outcome: 'invokes_registered_handler',
      },
    ],
  );
  for (const observation of projection.observations) {
    assert.equal(observation.semantic.action_id, observation.audit_subject_id);
    assert.ok(observation.chain.binding);
    assert.ok(observation.chain.stimulus);
    assert.ok(observation.chain.assertion);
    assert.ok(observation.chain.runtime_handler_invocation);
    assert.ok(observation.lineage.evidence.length >= 2);
    assert.ok(observation.native.suppression.length > 0);
    assert.ok(
      observation.defeats.every(
        item => item.impact === 'disjoint_from_positive_witness',
      ),
    );
  }
});

test('authority lock contains provenance only and models Ink as a React participant', async () => {
  const lock = JSON.parse(
    await readFile(path.join(defaultCorpusRoot(), 'authorities.lock.json'), 'utf8'),
  );
  assert.equal(lock.authorities.length, 17);
  assert.deepEqual(lock.recurrence.independent_authority_groups, [
    'react_dom',
    'vue_runtime_dom',
  ]);
  assert.deepEqual(lock.recurrence.same_system_participants, [
    'ink_terminal',
    'shadcn_react_dom',
    'mantine_react_dom',
  ]);
  for (const authority of lock.authorities) {
    assert.equal(Object.hasOwn(authority, 'establishes'), false);
    assert.equal(Object.hasOwn(authority, 'defeats'), false);
  }
  for (const authority of lock.authorities.filter(
    item => item.authority_group === 'ink_terminal',
  )) {
    assert.equal(authority.authority_class, 'same_system_participant');
  }
  const reconciler = lock.authorities.find(
    authority => authority.id === 'ink.reconciler.runtime',
  );
  assert.equal(reconciler?.source_path, 'src/reconciler.ts');
  assert.equal(
    reconciler?.sha256,
    'fd71eb685679e1954f6fe5fc91d6ddd6e44bd4ef66f88606059d2f8e02b6c3cc',
  );
});

test('every evidence span resolves to exactly one node in the pinned AST', async () => {
  const root = defaultCorpusRoot();
  const lock = JSON.parse(
    await readFile(path.join(root, 'authorities.lock.json'), 'utf8'),
  );
  const entries = new Map(lock.authorities.map(entry => [entry.id, entry]));
  const projection = await liftCorpus(root);
  const variants = projection.generator.parser.config.authority_variants;
  const parsed = new Map();

  for (const observation of projection.observations) {
    for (const item of evidenceItems(observation)) {
      const entry = entries.get(item.source);
      assert.ok(entry, item.source);
      const bytes = await readFile(path.join(root, entry.snapshot_path));
      const source = bytes.toString('utf8');
      const utf16Text = source.slice(item.span.utf16.start, item.span.utf16.end);
      const utf8Text = bytes
        .subarray(item.span.utf8_bytes.start, item.span.utf8_bytes.end)
        .toString('utf8');
      assert.equal(utf8Text, utf16Text, `${item.source} span encoding`);
      assert.ok(utf16Text.length > 0, `${item.source} empty evidence`);

      if (!parsed.has(item.source)) {
        parsed.set(
          item.source,
          parseAuthority(source, variants[item.source], entry.source_path),
        );
      }
      const matchingNodes = allNodes(
        parsed.get(item.source),
        node =>
          node.type === item.node_type &&
          node.start === item.span.utf16.start &&
          node.end === item.span.utf16.end,
      );
      assert.equal(
        matchingNodes.length,
        1,
        `${item.source} ${item.node_type} must resolve exactly`,
      );
    }
  }
});

test('checked-in projection is the exact deterministic generator output', async () => {
  const generated = encodeProjection(await liftCorpus());
  const checkedIn = await readFile(
    path.join(defaultCorpusRoot(), 'observations.lift.json'),
    'utf8',
  );
  assert.equal(checkedIn, generated);
});

for (const mutation of [
  {
    ecosystem: 'React',
    observation: 0,
    dimension: 'binding',
    chain: 'binding',
    replacement: 'data-gooir={onClick}',
    error: /React JSX onClick binding/,
  },
  {
    ecosystem: 'React',
    observation: 0,
    dimension: 'stimulus',
    chain: 'stimulus',
    replacement: 'void element',
    error: /React element.click stimulus/,
  },
  {
    ecosystem: 'React',
    observation: 0,
    dimension: 'assertion',
    chain: 'assertion',
    replacement: 'void onClick',
    error: /positive call-count assertion for onClick/,
  },
  {
    ecosystem: 'React',
    observation: 0,
    dimension: 'runtime handler',
    chain: 'runtime_handler_invocation',
    replacement: 'void event',
    error: /registered listener invocation/,
  },
  {
    ecosystem: 'Vue',
    observation: 1,
    dimension: 'binding',
    chain: 'binding',
    replacement: 'void fn',
    error: /Vue patchProp event binding/,
  },
  {
    ecosystem: 'Vue',
    observation: 1,
    dimension: 'stimulus',
    chain: 'stimulus',
    replacement: 'void el',
    error: /expected three Vue click dispatches/,
  },
  {
    ecosystem: 'Vue',
    observation: 1,
    dimension: 'assertion',
    chain: 'assertion',
    replacement: 'void fn',
    error: /positive call-count assertion for fn/,
  },
  {
    ecosystem: 'Vue',
    observation: 1,
    dimension: 'runtime handler',
    chain: 'runtime_handler_invocation',
    replacement: 'void value',
    error: /registered-handler invocation/,
  },
  {
    ecosystem: 'Ink',
    observation: 2,
    dimension: 'binding',
    chain: 'binding',
    replacement: 'void handleInput',
    error: /expected one active Ink useInput binding/,
  },
  {
    ecosystem: 'Ink',
    observation: 2,
    dimension: 'stimulus',
    chain: 'stimulus',
    replacement: 'void ps',
    error: /Ink PTY input stimulus/,
  },
  {
    ecosystem: 'Ink',
    observation: 2,
    dimension: 'assertion',
    chain: 'assertion',
    replacement: 'void ps',
    error: /Ink AVA true output assertion/,
  },
  {
    ecosystem: 'Ink',
    observation: 2,
    dimension: 'runtime handler',
    chain: 'runtime_handler_invocation',
    replacement: 'void input',
    error: /registered input-handler invocation/,
  },
]) {
  test(`${mutation.ecosystem} does not lift after its ${mutation.dimension} evidence is removed`, async () => {
    const temporaryRoot = await mkdtemp(
      path.join(os.tmpdir(), 'gooir-interaction-lift-'),
    );
    try {
      await cp(defaultCorpusRoot(), temporaryRoot, {recursive: true});
      const baseline = await liftCorpus(temporaryRoot);
      const evidence = baseline.observations[mutation.observation].chain[mutation.chain];
      const lockPath = path.join(temporaryRoot, 'authorities.lock.json');
      const lock = JSON.parse(await readFile(lockPath, 'utf8'));
      const authority = lock.authorities.find(item => item.id === evidence.source);
      assert.ok(authority);
      const sourcePath = path.join(temporaryRoot, authority.snapshot_path);
      const source = await readFile(sourcePath, 'utf8');
      const mutated =
        source.slice(0, evidence.span.utf16.start) +
        mutation.replacement +
        source.slice(evidence.span.utf16.end);
      await writeFile(sourcePath, mutated);
      authority.sha256 = sha256(Buffer.from(mutated, 'utf8'));
      await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

      await assert.rejects(() => liftCorpus(temporaryRoot), mutation.error);
    } finally {
      await rm(temporaryRoot, {recursive: true, force: true});
    }
  });
}

test('Ink cannot retain React-renderer lineage after its react-reconciler import is removed', async () => {
  const temporaryRoot = await mkdtemp(
    path.join(os.tmpdir(), 'gooir-interaction-lineage-'),
  );
  try {
    await cp(defaultCorpusRoot(), temporaryRoot, {recursive: true});
    const baseline = await liftCorpus(temporaryRoot);
    const evidence = baseline.observations[2].lineage.evidence.find(
      item => item.relation === 'imports_react_reconciler',
    );
    assert.ok(evidence);
    const lockPath = path.join(temporaryRoot, 'authorities.lock.json');
    const lock = JSON.parse(await readFile(lockPath, 'utf8'));
    const authority = lock.authorities.find(item => item.id === evidence.source);
    assert.ok(authority);
    const sourcePath = path.join(temporaryRoot, authority.snapshot_path);
    const source = await readFile(sourcePath, 'utf8');
    const mutated =
      source.slice(0, evidence.span.utf16.start) +
      'const createReconciler = undefined;' +
      source.slice(evidence.span.utf16.end);
    await writeFile(sourcePath, mutated);
    authority.sha256 = sha256(Buffer.from(mutated, 'utf8'));
    await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

    await assert.rejects(
      () => liftCorpus(temporaryRoot),
      /Ink react-reconciler import/,
    );
  } finally {
    await rm(temporaryRoot, {recursive: true, force: true});
  }
});

function evidenceItems(root) {
  const found = [];
  const pending = [root];
  while (pending.length > 0) {
    const value = pending.pop();
    if (!value || typeof value !== 'object') {
      continue;
    }
    if (
      typeof value.source === 'string' &&
      typeof value.node_type === 'string' &&
      value.span?.utf16 &&
      value.span?.utf8_bytes
    ) {
      found.push(value);
    }
    for (const child of Object.values(value)) {
      if (Array.isArray(child)) {
        pending.push(...child);
      } else if (child && typeof child === 'object') {
        pending.push(child);
      }
    }
  }
  return found;
}
