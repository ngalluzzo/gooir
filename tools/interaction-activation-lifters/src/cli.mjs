#!/usr/bin/env node

import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {defaultCorpusRoot, encodeProjection, liftCorpus} from './lift.mjs';

const argumentsToParse = process.argv.slice(2);
let check = false;
let corpusRoot = defaultCorpusRoot();
let output;

while (argumentsToParse.length > 0) {
  const argument = argumentsToParse.shift();
  if (argument === '--check') {
    check = true;
  } else if (argument === '--corpus') {
    corpusRoot = path.resolve(requiredValue(argument));
  } else if (argument === '--output') {
    output = path.resolve(requiredValue(argument));
  } else {
    throw new Error(`unknown argument ${JSON.stringify(argument)}`);
  }
}

output ??= path.join(corpusRoot, 'observations.lift.json');
const encoded = encodeProjection(await liftCorpus(corpusRoot));
if (check) {
  let checkedIn;
  try {
    checkedIn = await readFile(output, 'utf8');
  } catch (error) {
    throw new Error(`could not read generated observation ${output}: ${error.message}`, {
      cause: error,
    });
  }
  if (checkedIn !== encoded) {
    throw new Error(
      `${output} is stale; run npm run lift --prefix tools/interaction-activation-lifters`,
    );
  }
  process.stdout.write(`verified ${output}\n`);
} else {
  await writeFile(output, encoded);
  process.stdout.write(`wrote ${output}\n`);
}

function requiredValue(option) {
  const value = argumentsToParse.shift();
  if (!value) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}
