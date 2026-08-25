import {createHash} from 'node:crypto';
import vm from 'node:vm';

import React, {act} from 'react';
import TestRenderer from 'react-test-renderer';
import ts from 'typescript';

import {REVIEWED_USE_HISTORY_SHA256} from './react-history.mjs';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function compileReviewedHook(functionSource, filename) {
  if (sha256(functionSource) !== REVIEWED_USE_HISTORY_SHA256) {
    throw new Error(`${filename} is not the exact review-pinned function node`);
  }
  const source = `
    const {useState, useRef, useCallback, useMemo} = React;
    ${functionSource}
    globalThis.__gooir_useHistory = useHistory;
  `;
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
    throw new Error(`TypeScript rejected reviewed React hook ${filename}: ${errors.map(error => error.code).join(',')}`);
  }

  const context = vm.createContext(Object.create(null), {
    codeGeneration: {strings: false, wasm: false},
    name: filename,
  });
  Object.defineProperty(context, 'React', {value: React});
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
    ${output.outputText}
    if (typeof globalThis.__gooir_useHistory !== 'function') {
      throw new Error(${JSON.stringify(`${filename} did not produce useHistory`)});
    }
  `;
  new vm.Script(bootstrap, {filename}).runInContext(context, {timeout: 100});
  return context.__gooir_useHistory;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function execute(functionSource, fixture) {
  const useHistory = compileReviewedHook(functionSource, 'gemini-useHistory.ts');
  let current = null;
  let renderer = null;

  function Probe() {
    current = useHistory();
    return null;
  }

  const hadActEnvironment = Object.hasOwn(globalThis, 'IS_REACT_ACT_ENVIRONMENT');
  const previousActEnvironment = globalThis.IS_REACT_ACT_ENVIRONMENT;
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  try {
    act(() => {
      renderer = TestRenderer.create(React.createElement(Probe));
    });
    act(() => {
      current.loadHistory(clone(fixture.initial_history));
    });

    const allocatedIds = [];
    for (const action of fixture.actions) {
      act(() => {
        if (action.kind === 'add') {
          allocatedIds.push(current.addItem(clone(action.item), action.base_timestamp, true));
        } else if (action.kind === 'update') {
          current.updateItem(action.id, clone(action.updates));
        } else {
          throw new Error(`unsupported Gemini history action ${action.kind}`);
        }
      });
    }

    return {
      allocated_ids: allocatedIds,
      history: clone(current.history),
    };
  } finally {
    if (renderer) act(() => renderer.unmount());
    if (hadActEnvironment) globalThis.IS_REACT_ACT_ENVIRONMENT = previousActEnvironment;
    else delete globalThis.IS_REACT_ACT_ENVIRONMENT;
  }
}

async function readRequest() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

try {
  const request = await readRequest();
  process.stdout.write(JSON.stringify(execute(request.functionSource, request.fixture)));
} catch (error) {
  process.stderr.write(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
