import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseAuthority} from './ast.mjs';
import {liftInk} from './ink.mjs';
import {liftReact} from './react.mjs';
import {liftVue} from './vue.mjs';

export const OUTPUT_PROTOCOL =
  'org.gooi.fixture.interaction_activation_observations/v1';
export const AUTHORITY_PROTOCOL =
  'org.gooi.fixture.interaction_activation_authorities/v1';
export const TOOL_NAME = '@gooir/interaction-activation-lifters';
export const TOOL_VERSION = '0.1.0';
export const PARSER_NAME = '@babel/parser';
export const PARSER_VERSION = '7.29.8';

const TOOL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPOSITORY_ROOT = path.resolve(TOOL_ROOT, '../..');
const IMPLEMENTATION_PATHS = [
  'tools/interaction-activation-lifters/package.json',
  'tools/interaction-activation-lifters/src/ast.mjs',
  'tools/interaction-activation-lifters/src/cli.mjs',
  'tools/interaction-activation-lifters/src/ink.mjs',
  'tools/interaction-activation-lifters/src/lift.mjs',
  'tools/interaction-activation-lifters/src/react.mjs',
  'tools/interaction-activation-lifters/src/vue.mjs',
];
const PACKAGE_LOCK_PATH =
  'tools/interaction-activation-lifters/package-lock.json';
const AUTHORITY_PARSER_VARIANTS = {
  'react_dom.simple_event_plugin.runtime': 'typescript_jsx',
  'react_dom.dom_plugin_event_system.runtime': 'typescript_jsx',
  'react_dom.simple_event_plugin.conformance': 'flow_jsx',
  'vue_runtime_dom.events.runtime': 'typescript_jsx',
  'vue_runtime_dom.patch_events.conformance': 'typescript_jsx',
  'ink.use_input.runtime': 'typescript_jsx',
  'ink.reconciler.runtime': 'typescript_jsx',
  'ink.use_input_multiple.fixture': 'typescript_jsx',
  'ink.use_input.conformance': 'typescript_jsx',
};

export function defaultCorpusRoot() {
  return path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../../../fixtures/interaction/activation',
  );
}

export async function liftCorpus(corpusRoot = defaultCorpusRoot()) {
  const root = path.resolve(corpusRoot);
  const lockBytes = await readFile(path.join(root, 'authorities.lock.json'));
  const lock = JSON.parse(lockBytes.toString('utf8'));
  const context = await createContext(root, lock);
  const implementationSha256 = await aggregateImplementationSha256();
  const packageLockSha256 = sha256(
    await readFile(path.join(REPOSITORY_ROOT, PACKAGE_LOCK_PATH)),
  );

  const observations = [
    liftReact(context),
    liftVue(context),
    liftInk(context),
  ].map(observation => context.addUtf8Spans(observation));
  const seenSubjects = new Set();
  for (const observation of observations) {
    if (seenSubjects.has(observation.audit_subject_id)) {
      throw new Error(`duplicate audit subject ${observation.audit_subject_id}`);
    }
    seenSubjects.add(observation.audit_subject_id);
    if (observation.semantic.action_id !== observation.audit_subject_id) {
      throw new Error(
        `semantic action id does not preserve audit subject ${observation.audit_subject_id}`,
      );
    }
    for (const field of [
      'host',
      'binding_form',
      'stimulus_form',
      'assertion_form',
    ]) {
      if (typeof observation.native[field] !== 'string' || observation.native[field].length === 0) {
        throw new Error(`${observation.audit_subject_id} has no native ${field}`);
      }
    }
    if (!Array.isArray(observation.native.suppression) || observation.native.suppression.length === 0) {
      throw new Error(`${observation.audit_subject_id} has no established suppression evidence`);
    }
  }

  return {
    protocol: OUTPUT_PROTOCOL,
    generator: {
      name: TOOL_NAME,
      version: TOOL_VERSION,
      implementation_paths: IMPLEMENTATION_PATHS,
      implementation_sha256: implementationSha256,
      package_lock_path: PACKAGE_LOCK_PATH,
      package_lock_sha256: packageLockSha256,
      parser: {
        package: PARSER_NAME,
        version: PARSER_VERSION,
        config: {
          source_type: 'unambiguous',
          error_recovery: false,
          variants: {
            flow_jsx: {plugins: ['flow', 'jsx']},
            typescript_jsx: {plugins: ['typescript', 'jsx']},
          },
          authority_variants: AUTHORITY_PARSER_VARIANTS,
        },
      },
      authority_lock_sha256: sha256(lockBytes),
      evidence_kind: 'static_source_path_with_declared_test_corroboration',
    },
    observations,
  };
}

async function aggregateImplementationSha256() {
  const hash = createHash('sha256');
  for (const relativePath of IMPLEMENTATION_PATHS) {
    hash.update(relativePath, 'utf8');
    hash.update(new Uint8Array([0]));
    hash.update(await readFile(path.join(REPOSITORY_ROOT, relativePath)));
    hash.update(new Uint8Array([0]));
  }
  return hash.digest('hex');
}

async function createContext(root, lock) {
  if (lock.protocol !== AUTHORITY_PROTOCOL) {
    throw new Error(
      `authority protocol ${JSON.stringify(lock.protocol)} is not ${AUTHORITY_PROTOCOL}`,
    );
  }
  if (!Array.isArray(lock.authorities) || !Array.isArray(lock.licenses)) {
    throw new Error('authority lock must contain authorities and licenses arrays');
  }

  const entries = new Map();
  const contents = new Map();
  const snapshots = new Set();
  for (const entry of [...lock.authorities, ...lock.licenses]) {
    if (!safeRelativePath(entry.snapshot_path)) {
      throw new Error(`unsafe authority snapshot path ${JSON.stringify(entry.snapshot_path)}`);
    }
    if (snapshots.has(entry.snapshot_path)) {
      throw new Error(`duplicate authority snapshot ${entry.snapshot_path}`);
    }
    snapshots.add(entry.snapshot_path);
    if (!lowerHex(entry.repository?.commit, 40)) {
      throw new Error(`invalid full commit for ${entry.id ?? entry.ecosystem}`);
    }
    if (!lowerHex(entry.sha256, 64)) {
      throw new Error(`invalid SHA-256 for ${entry.id ?? entry.ecosystem}`);
    }
    if ('establishes' in entry || 'defeats' in entry) {
      throw new Error(
        `${entry.id ?? entry.ecosystem} carries a semantic verdict in the authority-only lock`,
      );
    }
    const bytes = await readFile(path.join(root, entry.snapshot_path));
    const actual = sha256(bytes);
    if (actual !== entry.sha256) {
      throw new Error(
        `digest mismatch for ${entry.id ?? entry.ecosystem}: expected ${entry.sha256}, observed ${actual}`,
      );
    }
    if (entry.id) {
      if (entries.has(entry.id)) {
        throw new Error(`duplicate authority id ${entry.id}`);
      }
      entries.set(entry.id, entry);
      contents.set(entry.id, bytes.toString('utf8'));
    }
  }
  for (const authority of lock.authorities) {
    const license = lock.licenses.find(
      entry => entry.snapshot_path === authority.license_snapshot,
    );
    if (
      !license ||
      license.repository.url !== authority.repository.url ||
      license.repository.commit !== authority.repository.commit
    ) {
      throw new Error(
        `${authority.id} does not reference a license pinned to the same repository revision`,
      );
    }
  }

  const asts = new Map();
  return {
    ast(id) {
      const entry = requiredEntry(entries, id);
      const language = AUTHORITY_PARSER_VARIANTS[id];
      if (!language) {
        throw new Error(`no parser variant is pinned for ${id}`);
      }
      const cacheKey = `${id}:${language}`;
      if (!asts.has(cacheKey)) {
        asts.set(
          cacheKey,
          parseAuthority(contents.get(id), language, entry.source_path),
        );
      }
      return asts.get(cacheKey);
    },
    sourceReferences(ids) {
      return ids.map(id => {
        const entry = requiredEntry(entries, id);
        return {
          authority_id: entry.id,
          repository: entry.repository,
          source_path: entry.source_path,
          snapshot_path: entry.snapshot_path,
          sha256: entry.sha256,
        };
      });
    },
    addUtf8Spans(observation) {
      visitObjects(observation, value => {
        if (
          typeof value.source !== 'string' ||
          typeof value.node_type !== 'string' ||
          value.span?.utf16 === undefined
        ) {
          return;
        }
        const source = contents.get(value.source);
        if (source === undefined) {
          throw new Error(`evidence names unknown authority ${value.source}`);
        }
        const {start, end} = value.span.utf16;
        if (
          !Number.isInteger(start) ||
          !Number.isInteger(end) ||
          start < 0 ||
          end <= start ||
          end > source.length
        ) {
          throw new Error(`invalid UTF-16 evidence span for ${value.source}`);
        }
        value.span.utf8_bytes = {
          start: Buffer.byteLength(source.slice(0, start), 'utf8'),
          end: Buffer.byteLength(source.slice(0, end), 'utf8'),
        };
      });
      return observation;
    },
    staticDefeats(authorityGroup) {
      return [
        {
          impact: 'disjoint_from_positive_witness',
          defeat: {
            kind: 'out_of_scope',
            subject: `${authorityGroup}.durable_conformance_run`,
            reason:
              'the lifter parsed an upstream test declaration but did not execute that upstream suite',
          },
        },
        {
          impact: 'disjoint_from_positive_witness',
          defeat: {
            kind: 'out_of_scope',
            subject: `${authorityGroup}.dependency_closure`,
            reason:
              'the authority corpus pins the callable path documents used by this observation, not the complete imported runtime closure',
          },
        },
      ];
    },
  };
}

function visitObjects(root, visit) {
  const pending = [root];
  while (pending.length > 0) {
    const value = pending.pop();
    if (!value || typeof value !== 'object') {
      continue;
    }
    visit(value);
    for (const child of Object.values(value)) {
      if (Array.isArray(child)) {
        pending.push(...child);
      } else if (child && typeof child === 'object') {
        pending.push(child);
      }
    }
  }
}

function requiredEntry(entries, id) {
  const entry = entries.get(id);
  if (!entry) {
    throw new Error(`authority lock has no ${id}`);
  }
  return entry;
}

function safeRelativePath(value) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    !path.isAbsolute(value) &&
    value.split(path.sep).every(part => part.length > 0 && part !== '.' && part !== '..')
  );
}

function lowerHex(value, length) {
  if (typeof value !== 'string' || value.length !== length) {
    return false;
  }
  for (const character of value) {
    const code = character.charCodeAt(0);
    const digit = code >= 48 && code <= 57;
    const lower = code >= 97 && code <= 102;
    if (!digit && !lower) {
      return false;
    }
  }
  return true;
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function encodeProjection(projection) {
  return `${JSON.stringify(projection, null, 2)}\n`;
}
