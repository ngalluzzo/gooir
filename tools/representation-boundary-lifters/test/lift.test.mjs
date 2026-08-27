import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

import { sha256 } from '../src/evidence.mjs';
import { encodeProjection, liftLock, LOCK_PROTOCOL, OUTPUT_PROTOCOL } from '../src/lift.mjs';

const run = promisify(execFile);
const TOOL_ROOT = path.resolve(import.meta.dirname, '..');
const CLI = path.join(TOOL_ROOT, 'src/cli.mjs');
const REPOSITORY = {
  url: 'https://example.com/acme/synthetic.git',
  commit: 'a'.repeat(40),
};

const SOURCES = {
  'snapshots/synthetic/View.tsx': `import React from 'react';
export const View = ({ items, ok }) => {
  if (!ok) return null;
  return <>
    <button onClick={() => {}}>Go</button>
    {ok ? <Panel /> : null}
    {items.map((item) => <span key={item}>{item}</span>)}
  </>;
};
`,
  'snapshots/synthetic/model.ts': `import type { Shape } from './shape.js';
export function area(shape: Shape): number { return shape.area; }
`,
  'snapshots/synthetic/Widget.vue': `<template>
  <RouterView />
  <component :is="kind" />
  <a-config-provider />
  <Teleport to="body"><button @click="go">{{ label }}</button></Teleport>
</template>
<script setup lang="ts">
const kind = 'aside';
const label = 'Open';
const go = () => {};
</script>
`,
  'snapshots/synthetic/manifest.json': `{"name":"sample","nested":{"enabled":true},"items":[{"id":1}]}
`,
  'snapshots/synthetic/index.html': '<main><button>raw</button></main>\n',
  'snapshots/synthetic/LICENSE': 'Synthetic license text.\n',
};

async function fixture(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'gooir-representation-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const [relative, contents] of Object.entries(SOURCES)) {
    const filename = path.join(directory, ...relative.split('/'));
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, contents);
  }

  const licenseSnapshot = 'snapshots/synthetic/LICENSE';
  const authority = (id, parserVariant, sourcePath, snapshotPath) => ({
    id,
    product_id: 'synthetic',
    role: 'native_source',
    parser_variant: parserVariant,
    repository: REPOSITORY,
    source_path: sourcePath,
    snapshot_path: snapshotPath,
    sha256: sha256(Buffer.from(SOURCES[snapshotPath])),
    license_snapshot: licenseSnapshot,
  });
  const lock = {
    protocol: LOCK_PROTOCOL,
    products: [
      {
        id: 'synthetic',
        governance_group: 'synthetic-governance',
        lifecycle: 'current',
        declared_ecosystem: 'mixed-test-only',
      },
    ],
    authorities: [
      authority('synthetic.tsx', 'typescript_jsx', 'src/View.tsx', 'snapshots/synthetic/View.tsx'),
      authority('synthetic.ts', 'typescript', 'src/model.ts', 'snapshots/synthetic/model.ts'),
      authority('synthetic.vue', 'vue_sfc', 'src/Widget.vue', 'snapshots/synthetic/Widget.vue'),
      authority('synthetic.json', 'json', 'manifest.json', 'snapshots/synthetic/manifest.json'),
      authority('synthetic.html', 'html', 'public/index.html', 'snapshots/synthetic/index.html'),
    ],
    licenses: [
      {
        id: 'synthetic.license',
        product_id: 'synthetic',
        repository: REPOSITORY,
        source_path: 'LICENSE',
        snapshot_path: licenseSnapshot,
        sha256: sha256(Buffer.from(SOURCES[licenseSnapshot])),
      },
    ],
  };
  const lockPath = path.join(directory, 'authorities.lock.json');
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  return {
    directory,
    lock,
    lockPath,
    async writeLock(nextLock) {
      await writeFile(lockPath, `${JSON.stringify(nextLock, null, 2)}\n`);
    },
  };
}

test('lifts parser-backed native inventories without representation claims', async (t) => {
  const { lockPath } = await fixture(t);
  const projection = await liftLock(lockPath);
  assert.equal(projection.protocol, OUTPUT_PROTOCOL);
  assert.match(projection.generator.implementation_sha256, /^[0-9a-f]{64}$/);
  assert.match(projection.generator.package_lock_sha256, /^[0-9a-f]{64}$/);
  assert.equal(projection.products.length, 1);
  const product = projection.products[0];
  assert.equal(product.summary.authority_count, 5);
  assert.deepEqual(product.summary.parser_variants, {
    typescript_jsx: 1,
    typescript: 1,
    vue_sfc: 1,
    json: 1,
    html: 1,
  });

  const byId = Object.fromEntries(
    product.authorities.map((authority) => [authority.authority_id, authority.native]),
  );
  assert.equal(byId['synthetic.tsx'].counts.imports, 1);
  assert.equal(byId['synthetic.tsx'].counts.exports, 1);
  assert.equal(byId['synthetic.tsx'].counts.jsx_tags, 3);
  assert.equal(byId['synthetic.tsx'].counts.jsx_fragments, 1);
  assert.equal(byId['synthetic.tsx'].counts.jsx_conditionals, 1);
  assert.equal(byId['synthetic.tsx'].counts.jsx_iterations, 1);
  assert.equal(byId['synthetic.tsx'].counts.return_nulls, 1);
  assert.equal(byId['synthetic.tsx'].counts.native_events, 1);
  assert.equal(byId['synthetic.vue'].counts.tags, 5);
  assert.equal(byId['synthetic.vue'].counts.directives, 2);
  assert.equal(byId['synthetic.vue'].counts.interpolations, 1);
  assert.equal(byId['synthetic.vue'].counts.dynamic_components, 1);
  assert.equal(byId['synthetic.vue'].counts.router_views, 1);
  assert.equal(byId['synthetic.vue'].counts.teleports, 1);
  assert.equal(
    byId['synthetic.vue'].tags.find((tag) => tag.name === 'a-config-provider').tag_type,
    'component',
  );
  assert.equal(byId['synthetic.json'].counts.keys, 5);
  assert.equal(byId['synthetic.html'].parsed, false);

  const serialized = encodeProjection(projection);
  assert.doesNotMatch(serialized, /"(screen|document|visibility|presentation|semantic)"/i);
  const eventEvidence = byId['synthetic.tsx'].native_events[0].evidence;
  assert.equal(
    SOURCES['snapshots/synthetic/View.tsx'].slice(
      eventEvidence.span.utf16.start,
      eventEvidence.span.utf16.end,
    ),
    'onClick={() => {}}',
  );
});

test('projection is deterministic and authority ordering is canonical', async (t) => {
  const source = await fixture(t);
  const first = encodeProjection(await liftLock(source.lockPath));
  const reversed = structuredClone(source.lock);
  reversed.products.reverse();
  reversed.authorities.reverse();
  reversed.licenses.reverse();
  await source.writeLock(reversed);
  const reordered = encodeProjection(await liftLock(source.lockPath));
  const second = encodeProjection(await liftLock(source.lockPath));
  assert.equal(reordered, second);
  assert.notEqual(first, reordered, 'exact input lock bytes remain provenance-bound');
  assert.deepEqual(
    JSON.parse(reordered).products[0].authorities.map((authority) => authority.authority_id),
    [
      'synthetic.html',
      'synthetic.json',
      'synthetic.ts',
      'synthetic.tsx',
      'synthetic.vue',
    ],
  );
});

test('rejects a snapshot digest mismatch', async (t) => {
  const source = await fixture(t);
  const mutated = structuredClone(source.lock);
  mutated.authorities[0].sha256 = '0'.repeat(64);
  await source.writeLock(mutated);
  await assert.rejects(liftLock(source.lockPath), /snapshot digest mismatch/);
});

test('rejects unsafe and duplicate snapshot paths', async (t) => {
  const source = await fixture(t);
  const unsafe = structuredClone(source.lock);
  unsafe.authorities[0].snapshot_path = '../outside.tsx';
  await source.writeLock(unsafe);
  await assert.rejects(liftLock(source.lockPath), /safe normalized relative POSIX path/);

  const duplicate = structuredClone(source.lock);
  duplicate.authorities[1].snapshot_path = duplicate.authorities[0].snapshot_path;
  duplicate.authorities[1].sha256 = duplicate.authorities[0].sha256;
  await source.writeLock(duplicate);
  await assert.rejects(liftLock(source.lockPath), /snapshot paths contains duplicate/);
});

test('rejects authored semantic verdict fields and unknown fields', async (t) => {
  const source = await fixture(t);
  const semantic = structuredClone(source.lock);
  semantic.authorities[0].semantic = { screen: true };
  await source.writeLock(semantic);
  await assert.rejects(liftLock(source.lockPath), /prohibited authored verdict field semantic/);

  const unknown = structuredClone(source.lock);
  unknown.products[0].governance_grop = unknown.products[0].governance_group;
  delete unknown.products[0].governance_group;
  await source.writeLock(unknown);
  await assert.rejects(liftLock(source.lockPath), /unknown field governance_grop/);

  const interpretiveRole = structuredClone(source.lock);
  interpretiveRole.authorities[0].role = 'screen_projection';
  await source.writeLock(interpretiveRole);
  await assert.rejects(liftLock(source.lockPath), /role is not a neutral artifact class/);
});

test('rejects source text rejected by Babel after its digest is updated', async (t) => {
  const source = await fixture(t);
  const invalid = 'export const Broken = <div>\n';
  await writeFile(path.join(source.directory, 'snapshots/synthetic/View.tsx'), invalid);
  const mutated = structuredClone(source.lock);
  mutated.authorities[0].sha256 = sha256(Buffer.from(invalid));
  await source.writeLock(mutated);
  await assert.rejects(liftLock(source.lockPath), /Babel rejected/);
});

test('rejects source text rejected by the Vue parsers after its digest is updated', async (t) => {
  const source = await fixture(t);
  const invalid = '<template><div></template>\n';
  await writeFile(path.join(source.directory, 'snapshots/synthetic/Widget.vue'), invalid);
  const mutated = structuredClone(source.lock);
  const vue = mutated.authorities.find((authority) => authority.id === 'synthetic.vue');
  vue.sha256 = sha256(Buffer.from(invalid));
  await source.writeLock(mutated);
  await assert.rejects(liftLock(source.lockPath), /Vue (SFC|template) parser rejected/);
});

test('CLI lift writes exact bytes and check fails closed on drift', async (t) => {
  const source = await fixture(t);
  const output = path.join(source.directory, 'native-observations.lift.json');
  await run(process.execPath, [CLI, '--lock', source.lockPath, '--output', output], {
    cwd: TOOL_ROOT,
  });
  const actual = await readFile(output, 'utf8');
  const expected = encodeProjection(await liftLock(source.lockPath));
  assert.equal(actual, expected);
  await run(process.execPath, [CLI, '--check', '--lock', source.lockPath, '--output', output], {
    cwd: TOOL_ROOT,
  });
  await writeFile(output, `${actual} `);
  await assert.rejects(
    run(process.execPath, [CLI, '--check', '--lock', source.lockPath, '--output', output], {
      cwd: TOOL_ROOT,
    }),
    /generated projection differs/,
  );
});
