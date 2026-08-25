#!/usr/bin/env node

import {execFile} from 'node:child_process';
import {mkdtemp, mkdir, readFile, realpath, rename, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {promisify} from 'node:util';

import {sha256} from './evidence.mjs';
import {validateLock} from './lift.mjs';

const run = promisify(execFile);

function inside(base, candidate) {
  const relative = path.relative(base, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function checkout(repository, workspace) {
  const directory = path.join(workspace, sha256(`${repository.url}\0${repository.commit}`));
  await mkdir(directory);
  const options = {cwd: directory, env: {...process.env, GIT_TERMINAL_PROMPT: '0'}, maxBuffer: 10 * 1024 * 1024};
  await run('git', ['init', '--quiet'], options);
  await run('git', ['remote', 'add', 'origin', repository.url], options);
  await run('git', ['config', 'remote.origin.promisor', 'true'], options);
  await run('git', ['config', 'remote.origin.partialclonefilter', 'blob:none'], options);
  await run('git', ['fetch', '--quiet', '--no-tags', '--depth=1', '--filter=blob:none', 'origin', repository.commit], options);
  const {stdout} = await run('git', ['rev-parse', 'FETCH_HEAD'], options);
  if (stdout.trim() !== repository.commit) throw new Error(`${repository.url} resolved an unexpected revision`);
  return directory;
}

async function source(directory, entry) {
  const {stdout} = await run('git', ['show', `${entry.repository.commit}:${entry.source_path}`], {
    cwd: directory,
    encoding: 'buffer',
    maxBuffer: 60 * 1024 * 1024,
    env: {...process.env, GIT_TERMINAL_PROMPT: '0'},
  });
  return stdout;
}

async function replace(root, relative, bytes) {
  const destination = path.resolve(root, ...relative.split('/'));
  if (!inside(root, destination)) throw new Error(`${relative} escapes corpus root`);
  await mkdir(path.dirname(destination), {recursive: true});
  const parent = await realpath(path.dirname(destination));
  if (!inside(root, parent)) throw new Error(`${relative} resolves outside corpus root`);
  const temporary = path.join(parent, `.activity-refresh-${process.pid}-${Math.random().toString(16).slice(2)}`);
  try {
    await writeFile(temporary, bytes, {flag: 'wx'});
    await rename(temporary, destination);
  } finally {
    await rm(temporary, {force: true});
  }
}

export async function refresh(lockPath) {
  const absolute = path.resolve(lockPath);
  const root = await realpath(path.dirname(absolute));
  const lock = JSON.parse(await readFile(absolute, 'utf8'));
  validateLock(lock);
  const workspace = await mkdtemp(path.join(tmpdir(), 'gooir-activity-refresh-'));
  try {
    const checkouts = new Map();
    const verified = [];
    for (const entry of [...lock.authorities, ...lock.licenses].toSorted((left, right) => left.snapshot_path.localeCompare(right.snapshot_path))) {
      const key = `${entry.repository.url}\0${entry.repository.commit}`;
      let directory = checkouts.get(key);
      if (!directory) {
        directory = await checkout(entry.repository, workspace);
        checkouts.set(key, directory);
      }
      const bytes = await source(directory, entry);
      const actual = sha256(bytes);
      if (actual !== entry.sha256) throw new Error(`${entry.id} expected ${entry.sha256}, received ${actual}`);
      verified.push({entry, bytes});
    }
    for (const {entry, bytes} of verified) await replace(root, entry.snapshot_path, bytes);
  } finally {
    await rm(workspace, {recursive: true, force: true});
  }
}

const values = process.argv.slice(2);
if (values.length !== 2 || values[0] !== '--lock') {
  process.stderr.write('usage: refresh.mjs --lock <path>\n');
  process.exitCode = 1;
} else {
  refresh(values[1]).catch(error => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
}
