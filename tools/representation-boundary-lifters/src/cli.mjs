#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { encodeProjection, liftLock } from './lift.mjs';

function usage() {
  return 'usage: cli.mjs [--check] --lock <path> --output <path>';
}

function parseArguments(arguments_) {
  let check = false;
  let lock = null;
  let output = null;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === '--check') {
      check = true;
    } else if (argument === '--lock' || argument === '--output') {
      const value = arguments_[index + 1];
      if (!value || value.startsWith('--')) throw new Error(`${argument} requires a path`);
      if (argument === '--lock') lock = value;
      else output = value;
      index += 1;
    } else {
      throw new Error(`unknown argument ${argument}`);
    }
  }
  if (!lock) throw new Error('--lock is required');
  output ??= path.join(path.dirname(path.resolve(lock)), 'native-observations.lift.json');
  if (path.resolve(lock) === path.resolve(output)) {
    throw new Error('--output must not overwrite --lock');
  }
  return { check, lock, output };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const expected = encodeProjection(await liftLock(options.lock));
  if (options.check) {
    const actual = await readFile(options.output, 'utf8');
    if (actual !== expected) {
      throw new Error(`generated projection differs from ${path.resolve(options.output)}`);
    }
  } else {
    await writeFile(options.output, expected);
  }
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n${usage()}\n`);
  process.exitCode = 1;
});
