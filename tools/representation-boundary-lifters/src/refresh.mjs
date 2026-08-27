#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { sha256 } from './evidence.mjs';
import { validateLockShape } from './lift.mjs';

const run = promisify(execFile);

function parseArguments(arguments_) {
  if (arguments_.length !== 2 || arguments_[0] !== '--lock') {
    throw new Error('usage: refresh.mjs --lock <path>');
  }
  return path.resolve(arguments_[1]);
}

function inside(base, candidate) {
  const relative = path.relative(base, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

async function readSource(repositoryDirectory, repository, sourcePath) {
  if (sourcePath.includes(':') || sourcePath.includes('\0') || sourcePath.includes('\\')) {
    throw new Error(`source path is unsafe for git object lookup: ${sourcePath}`);
  }
  try {
    const { stdout } = await run(
      'git',
      ['show', `${repository.commit}:${sourcePath}`],
      {
        cwd: repositoryDirectory,
        encoding: 'buffer',
        maxBuffer: 50 * 1024 * 1024,
        env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
      },
    );
    return stdout;
  } catch (error) {
    throw new Error(`cannot read ${sourcePath} at ${repository.commit}: ${error.message}`, {
      cause: error,
    });
  }
}

async function writeSnapshot(lockDirectory, snapshotPath, bytes) {
  const destination = path.resolve(lockDirectory, ...snapshotPath.split('/'));
  if (!inside(lockDirectory, destination)) {
    throw new Error(`snapshot path escapes lock directory: ${snapshotPath}`);
  }
  const parent = path.dirname(destination);
  await mkdir(parent, { recursive: true });
  const resolvedParent = await realpath(parent);
  if (!inside(lockDirectory, resolvedParent)) {
    throw new Error(`snapshot parent resolves outside lock directory: ${snapshotPath}`);
  }
  const temporary = path.join(
    resolvedParent,
    `.gooir-refresh-${process.pid}-${Math.random().toString(16).slice(2)}.tmp`,
  );
  try {
    await writeFile(temporary, bytes, { flag: 'wx' });
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
}

async function checkout(repository, workspace) {
  const directory = path.join(workspace, sha256(`${repository.url}\0${repository.commit}`));
  await mkdir(directory);
  const options = {
    cwd: directory,
    maxBuffer: 10 * 1024 * 1024,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
  };
  await run('git', ['init', '--quiet'], options);
  await run('git', ['remote', 'add', 'origin', repository.url], options);
  await run('git', ['config', 'remote.origin.promisor', 'true'], options);
  await run('git', ['config', 'remote.origin.partialclonefilter', 'blob:none'], options);
  await run(
    'git',
    ['fetch', '--quiet', '--no-tags', '--depth=1', '--filter=blob:none', 'origin', repository.commit],
    options,
  );
  const { stdout } = await run('git', ['rev-parse', 'FETCH_HEAD'], options);
  if (stdout.trim() !== repository.commit) {
    throw new Error(`git resolved ${repository.url} to an unexpected revision`);
  }
  return directory;
}

export async function refreshLock(lockPath) {
  const absoluteLockPath = path.resolve(lockPath);
  const lockDirectory = await realpath(path.dirname(absoluteLockPath));
  const lock = JSON.parse(await readFile(absoluteLockPath, 'utf8'));
  validateLockShape(lock);
  const workspace = await mkdtemp(path.join(tmpdir(), 'gooir-representation-refresh-'));
  try {
    const checkouts = new Map();
    const entries = [...lock.authorities, ...lock.licenses].sort((left, right) =>
      left.snapshot_path.localeCompare(right.snapshot_path),
    );
    for (const entry of entries) {
      if (path.resolve(lockDirectory, ...entry.snapshot_path.split('/')) === absoluteLockPath) {
        throw new Error(`snapshot ${entry.snapshot_path} must not overwrite its authority lock`);
      }
    }
    const verified = [];
    for (const entry of entries) {
      const key = `${entry.repository.url}\0${entry.repository.commit}`;
      let repositoryDirectory = checkouts.get(key);
      if (!repositoryDirectory) {
        repositoryDirectory = await checkout(entry.repository, workspace);
        checkouts.set(key, repositoryDirectory);
      }
      const bytes = await readSource(repositoryDirectory, entry.repository, entry.source_path);
      const actual = sha256(bytes);
      if (actual !== entry.sha256) {
        throw new Error(
          `upstream digest mismatch for ${entry.id}: expected ${entry.sha256}, received ${actual}`,
        );
      }
      verified.push({ entry, bytes });
    }
    for (const { entry, bytes } of verified) {
      await writeSnapshot(lockDirectory, entry.snapshot_path, bytes);
    }
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

async function main() {
  await refreshLock(parseArguments(process.argv.slice(2)));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
