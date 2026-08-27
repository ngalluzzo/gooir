#!/usr/bin/env node

import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';

import {defaultCorpusRoot, encode, liftCorpus} from './lift.mjs';

function argumentsOf(values) {
  const out = {check: false, root: defaultCorpusRoot(), output: null};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === '--check') out.check = true;
    else if (value === '--root') out.root = path.resolve(values[++index]);
    else if (value === '--output') out.output = path.resolve(values[++index]);
    else throw new Error(`unknown argument ${value}`);
  }
  out.output ??= path.join(out.root, 'observations.lift.json');
  return out;
}

async function main() {
  const options = argumentsOf(process.argv.slice(2));
  const generated = encode(await liftCorpus(options.root));
  if (options.check) {
    const checked = await readFile(options.output, 'utf8');
    if (checked !== generated) throw new Error(`generated observations differ from ${options.output}`);
  } else {
    await writeFile(options.output, generated);
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
