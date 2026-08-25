import {parse} from '@babel/parser';
import Parser from 'tree-sitter';
import Python from 'tree-sitter-python';
import Rust from 'tree-sitter-rust';
import {parse as parseSvelte} from 'svelte/compiler';
import {parse as parseToml} from 'smol-toml';
import ts from 'typescript';
import vm from 'node:vm';

export function parseTypescript(source, filename, jsx = false) {
  try {
    return parse(source, {
      sourceType: 'unambiguous',
      errorRecovery: false,
      sourceFilename: filename,
      plugins: ['typescript', ...(jsx ? ['jsx'] : [])],
    });
  } catch (error) {
    throw new Error(`Babel rejected ${filename}: ${error.message}`, {cause: error});
  }
}

export function parseSvelteSource(source, filename) {
  try {
    return parseSvelte(source, {filename, modern: true});
  } catch (error) {
    throw new Error(`Svelte compiler rejected ${filename}: ${error.message}`, {cause: error});
  }
}

function parseTreeSitter(source, filename, language) {
  const parser = new Parser();
  parser.setLanguage(language);
  const tree = parser.parse(source);
  if (tree.rootNode.hasError) throw new Error(`tree-sitter rejected ${filename}`);
  return tree;
}

export function parsePython(source, filename) {
  return parseTreeSitter(source, filename, Python);
}

export function parseRust(source, filename) {
  return parseTreeSitter(source, filename, Rust);
}

export function parseTomlSource(source, filename) {
  try {
    return parseToml(source);
  } catch (error) {
    throw new Error(`TOML parser rejected ${filename}: ${error.message}`, {cause: error});
  }
}

export function executeExportedTypescript(source, filename, exportName) {
  const output = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      strict: true,
    },
    fileName: filename,
    reportDiagnostics: true,
  });
  const errors = (output.diagnostics ?? []).filter(diagnostic => diagnostic.category === ts.DiagnosticCategory.Error);
  if (errors.length > 0) {
    throw new Error(`TypeScript rejected extracted ${filename}: ${errors.map(error => error.code).join(',')}`);
  }
  const context = vm.createContext(Object.create(null), {
    codeGeneration: {strings: false, wasm: false},
    name: filename,
  });
  const bootstrap = `
    'use strict';
    Object.defineProperties(globalThis, {
      process: {value: undefined},
      require: {value: undefined},
      fetch: {value: undefined},
      WebSocket: {value: undefined},
      Date: {value: undefined},
      performance: {value: undefined},
      setTimeout: {value: undefined},
      setInterval: {value: undefined}
    });
    const module = Object.create(null);
    module.exports = Object.create(null);
    const exports = module.exports;
    ${output.outputText}
    globalThis.__gooir_callable = module.exports[${JSON.stringify(exportName)}];
    if (typeof globalThis.__gooir_callable !== 'function') {
      throw new Error(${JSON.stringify(`${filename} did not export ${exportName}`)});
    }
  `;
  new vm.Script(bootstrap, {filename}).runInContext(context, {timeout: 100});

  return (...args) => {
    const encodedArgs = JSON.stringify(args);
    if (encodedArgs === undefined) throw new Error(`${filename} arguments are not JSON values`);
    const invocation = `JSON.stringify(globalThis.__gooir_callable(...${encodedArgs}))`;
    const encodedResult = new vm.Script(invocation, {filename}).runInContext(context, {timeout: 100});
    if (typeof encodedResult !== 'string') throw new Error(`${filename} returned a non-JSON value`);
    return JSON.parse(encodedResult);
  };
}

export function walkBabel(root, visit) {
  const pending = [root];
  while (pending.length > 0) {
    const node = pending.pop();
    if (!node || typeof node !== 'object') continue;
    if (typeof node.type === 'string') visit(node);
    for (const [key, child] of Object.entries(node)) {
      if (key === 'loc' || key === 'tokens' || key === 'comments') continue;
      if (Array.isArray(child)) pending.push(...child);
      else if (child && typeof child === 'object') pending.push(child);
    }
  }
}

export function findBabel(root, predicate, subject) {
  const matches = [];
  walkBabel(root, node => {
    if (predicate(node)) matches.push(node);
  });
  if (matches.length !== 1) throw new Error(`${subject} expected one AST match, found ${matches.length}`);
  return matches[0];
}

export function findTreeNodes(root, predicate) {
  const matches = [];
  const pending = [root];
  while (pending.length > 0) {
    const node = pending.pop();
    if (predicate(node)) matches.push(node);
    for (let index = node.namedChildCount - 1; index >= 0; index -= 1) pending.push(node.namedChild(index));
  }
  return matches;
}
