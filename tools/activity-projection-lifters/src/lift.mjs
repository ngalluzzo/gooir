import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

import {sha256} from './evidence.mjs';
import {findTreeNodes, parsePython, parseRust, parseSvelteSource, parseTomlSource, parseTypescript} from './parsers.mjs';
import {
  projectChatUi,
  projectCodex,
  projectGemini,
  projectLibre,
  projectLobe,
  projectOpenWeb,
  runBehavioralCases,
} from './projectors.mjs';

export const LOCK_PROTOCOL = 'org.gooi.fixture.activity_projection_authorities/v1';
export const OUTPUT_PROTOCOL = 'org.gooi.fixture.activity_projection_observations/v1';
const TOOL_NAME = '@gooir/activity-projection-lifters';
const TOOL_VERSION = '0.1.0';
const TOOL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGE_LOCK_PATH = 'package-lock.json';
const IMPLEMENTATION_PATHS = [
  'package.json',
  'src/cli.mjs',
  'src/evidence.mjs',
  'src/lift.mjs',
  'src/parsers.mjs',
  'src/projectors.mjs',
  'src/refresh.mjs',
];
const PRODUCT_FIELDS = new Set(['id', 'governance_group', 'declared_ecosystem', 'projector']);
const AUTHORITY_FIELDS = new Set(['id', 'product_id', 'role', 'parser_variant', 'repository', 'source_path', 'snapshot_path', 'sha256', 'license_snapshot']);
const LICENSE_FIELDS = new Set(['id', 'product_id', 'repository', 'source_path', 'snapshot_path', 'sha256']);
const REPOSITORY_FIELDS = new Set(['url', 'commit']);
const PARSER_VARIANTS = new Set(['typescript', 'typescript_jsx', 'svelte', 'python', 'rust', 'json', 'toml']);
const PROJECTORS = new Set(['lobe', 'libre', 'open_web', 'chat_ui', 'gemini', 'codex']);
const ROLES = new Set(['manifest', 'state_source', 'type_source', 'projection_source', 'consumer_source', 'runtime_manifest']);
const FORBIDDEN = new Set(['semantic', 'establishes', 'defeats', 'claim']);
const RESERVED_SNAPSHOT_PATHS = new Set(['authorities.lock.json', 'observations.lift.json']);
const REJECTED_CANDIDATES = Object.freeze([
  'canonical_transcript',
  'global_chronology',
  'universal_actor_enum',
  'portable_payload',
  'backing_branch_graph',
  'singular_current_input_or_decision_locus',
  'stream_delta_as_durable_activity',
]);

export function defaultCorpusRoot() {
  return path.resolve(TOOL_ROOT, '../../fixtures/activity/projection');
}

function assertObject(value, subject) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${subject} must be an object`);
}

function exactFields(value, fields, subject) {
  assertObject(value, subject);
  for (const key of Object.keys(value)) if (!fields.has(key)) throw new Error(`${subject} has unknown field ${key}`);
  for (const key of fields) if (!Object.hasOwn(value, key)) throw new Error(`${subject} is missing field ${key}`);
}

function rejectVerdicts(value, subject = 'lock') {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) return value.forEach((child, index) => rejectVerdicts(child, `${subject}[${index}]`));
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN.has(key)) throw new Error(`${subject} contains prohibited verdict field ${key}`);
    rejectVerdicts(child, `${subject}.${key}`);
  }
}

function string(value, subject) {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) throw new Error(`${subject} must be a nonempty trimmed string`);
}

function digest(value, length, subject) {
  string(value, subject);
  if (!new RegExp(`^[0-9a-f]{${length}}$`).test(value)) throw new Error(`${subject} must be ${length} lowercase hex characters`);
}

function safePath(value, subject) {
  string(value, subject);
  if (value.includes('\\') || value.includes(':') || value.includes('\0') || path.posix.isAbsolute(value) || value.split('/').some(part => part === '' || part === '.' || part === '..') || path.posix.normalize(value) !== value) {
    throw new Error(`${subject} must be a safe normalized relative POSIX path`);
  }
}

function repository(value, subject) {
  exactFields(value, REPOSITORY_FIELDS, subject);
  string(value.url, `${subject}.url`);
  if (new URL(value.url).protocol !== 'https:') throw new Error(`${subject}.url must use https`);
  digest(value.commit, 40, `${subject}.commit`);
}

function unique(values, subject) {
  const seen = new Set();
  for (const value of values) {
    if (seen.has(value)) throw new Error(`${subject} contains duplicate ${value}`);
    seen.add(value);
  }
}

export function validateLock(lock) {
  exactFields(lock, new Set(['protocol', 'products', 'authorities', 'licenses']), 'lock');
  rejectVerdicts(lock);
  if (lock.protocol !== LOCK_PROTOCOL) throw new Error(`unsupported lock protocol ${lock.protocol}`);
  for (const key of ['products', 'authorities', 'licenses']) if (!Array.isArray(lock[key]) || lock[key].length === 0) throw new Error(`lock.${key} must be a nonempty array`);

  lock.products.forEach((product, index) => {
    const subject = `lock.products[${index}]`;
    exactFields(product, PRODUCT_FIELDS, subject);
    for (const key of ['id', 'governance_group', 'declared_ecosystem', 'projector']) string(product[key], `${subject}.${key}`);
    if (!PROJECTORS.has(product.projector)) throw new Error(`${subject}.projector is unsupported`);
  });
  unique(lock.products.map(product => product.id), 'product ids');
  unique(lock.products.map(product => product.governance_group), 'governance groups');
  unique(lock.products.map(product => product.projector), 'projectors');

  lock.authorities.forEach((entry, index) => {
    const subject = `lock.authorities[${index}]`;
    exactFields(entry, AUTHORITY_FIELDS, subject);
    for (const key of ['id', 'product_id', 'role', 'parser_variant']) string(entry[key], `${subject}.${key}`);
    if (!ROLES.has(entry.role)) throw new Error(`${subject}.role is not neutral`);
    if (!PARSER_VARIANTS.has(entry.parser_variant)) throw new Error(`${subject}.parser_variant is unsupported`);
    repository(entry.repository, `${subject}.repository`);
    safePath(entry.source_path, `${subject}.source_path`);
    safePath(entry.snapshot_path, `${subject}.snapshot_path`);
    if (RESERVED_SNAPSHOT_PATHS.has(entry.snapshot_path)) throw new Error(`${subject}.snapshot_path is reserved control state`);
    safePath(entry.license_snapshot, `${subject}.license_snapshot`);
    digest(entry.sha256, 64, `${subject}.sha256`);
  });

  lock.licenses.forEach((entry, index) => {
    const subject = `lock.licenses[${index}]`;
    exactFields(entry, LICENSE_FIELDS, subject);
    string(entry.id, `${subject}.id`);
    string(entry.product_id, `${subject}.product_id`);
    repository(entry.repository, `${subject}.repository`);
    safePath(entry.source_path, `${subject}.source_path`);
    safePath(entry.snapshot_path, `${subject}.snapshot_path`);
    if (RESERVED_SNAPSHOT_PATHS.has(entry.snapshot_path)) throw new Error(`${subject}.snapshot_path is reserved control state`);
    digest(entry.sha256, 64, `${subject}.sha256`);
  });
  unique(lock.authorities.map(entry => entry.id), 'authority ids');
  unique(lock.licenses.map(entry => entry.id), 'license ids');
  unique([...lock.authorities, ...lock.licenses].map(entry => entry.snapshot_path), 'snapshot paths');

  const products = new Set(lock.products.map(product => product.id));
  for (const entry of lock.authorities) {
    if (!products.has(entry.product_id)) throw new Error(`${entry.id} names unknown product ${entry.product_id}`);
    const license = lock.licenses.find(candidate => candidate.product_id === entry.product_id && candidate.snapshot_path === entry.license_snapshot);
    if (!license || license.repository.url !== entry.repository.url || license.repository.commit !== entry.repository.commit) throw new Error(`${entry.id} has no same-revision product license`);
  }
  for (const product of lock.products) {
    if (!lock.authorities.some(entry => entry.product_id === product.id)) throw new Error(`${product.id} has no authority`);
    if (!lock.licenses.some(entry => entry.product_id === product.id)) throw new Error(`${product.id} has no license`);
  }
}

async function implementationDigest() {
  const hash = createHash('sha256');
  for (const relative of IMPLEMENTATION_PATHS) {
    hash.update(relative);
    hash.update('\0');
    hash.update(await readFile(path.join(TOOL_ROOT, relative)));
    hash.update('\0');
  }
  return hash.digest('hex');
}

function treeNamed(root, type, name) {
  const matches = findTreeNodes(root, node => node.type === type && node.childForFieldName('name')?.text === name);
  if (matches.length !== 1) throw new Error(`${type} ${name} expected once, found ${matches.length}`);
  return matches[0];
}

async function createContext(root, lock) {
  const entries = new Map();
  const parsed = new Map();
  for (const entry of [...lock.authorities, ...lock.licenses]) {
    const bytes = await readFile(path.join(root, entry.snapshot_path));
    if (sha256(bytes) !== entry.sha256) throw new Error(`snapshot digest mismatch for ${entry.id}`);
    if (!entry.parser_variant) continue;
    const source = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
    entries.set(entry.id, {...entry, bytes, source});
  }
  for (const entry of entries.values()) {
    let ast;
    if (entry.parser_variant === 'typescript') ast = parseTypescript(entry.source, entry.source_path, false);
    else if (entry.parser_variant === 'typescript_jsx') ast = parseTypescript(entry.source, entry.source_path, true);
    else if (entry.parser_variant === 'svelte') ast = parseSvelteSource(entry.source, entry.source_path);
    else if (entry.parser_variant === 'python') ast = parsePython(entry.source, entry.source_path);
    else if (entry.parser_variant === 'rust') ast = parseRust(entry.source, entry.source_path);
    else if (entry.parser_variant === 'json') ast = JSON.parse(entry.source);
    else if (entry.parser_variant === 'toml') ast = parseTomlSource(entry.source, entry.source_path);
    parsed.set(entry.id, {...entry, ast});
  }
  const get = id => {
    const entry = entries.get(id);
    if (!entry) throw new Error(`authority ${id} is missing`);
    return entry;
  };
  const parse = (id, expected, run) => {
    const entry = get(id);
    if (entry.parser_variant !== expected) throw new Error(`${id} parser variant is ${entry.parser_variant}, expected ${expected}`);
    if (!parsed.has(id)) parsed.set(id, {...entry, ast: run(entry.source, entry.source_path)});
    return parsed.get(id);
  };
  return {
    entries(productId) {
      return lock.authorities.filter(entry => entry.product_id === productId);
    },
    ts(id, jsx = false) {
      return parse(id, jsx ? 'typescript_jsx' : 'typescript', source => parseTypescript(source, get(id).source_path, jsx));
    },
    svelte(id) {
      return parse(id, 'svelte', source => parseSvelteSource(source, get(id).source_path));
    },
    python(id) {
      const entry = parse(id, 'python', source => parsePython(source, get(id).source_path));
      return {...entry, tree: entry.ast};
    },
    rust(id) {
      const entry = parse(id, 'rust', source => parseRust(source, get(id).source_path));
      return {...entry, tree: entry.ast};
    },
    treeClass(entry, name) {
      return treeNamed(entry.tree.rootNode, 'class_definition', name);
    },
    treeStruct(entry, name) {
      return treeNamed(entry.tree.rootNode, 'struct_item', name);
    },
    treeEnum(entry, name) {
      return treeNamed(entry.tree.rootNode, 'enum_item', name);
    },
    requireTreeText(entry, node, fragment) {
      const text = entry.bytes.subarray(node.startIndex, node.endIndex).toString('utf8');
      if (!text.includes(fragment)) throw new Error(`${entry.id} ${node.type} no longer contains ${fragment}`);
    },
  };
}

const PROJECT = {
  lobe: projectLobe,
  libre: projectLibre,
  open_web: projectOpenWeb,
  chat_ui: projectChatUi,
  gemini: projectGemini,
  codex: projectCodex,
};

function validateDefeats(observations) {
  const rejected = new Set(REJECTED_CANDIDATES);
  for (const observation of observations) {
    if (!Array.isArray(observation.defeats) || observation.defeats.length === 0) throw new Error(`${observation.product_id} must retain typed limits`);
    for (const defeat of observation.defeats) {
      exactFields(defeat, new Set(['kind', 'affects', 'impact', 'subject', 'reason']), `${observation.product_id} defeat`);
      for (const field of ['kind', 'affects', 'impact', 'subject', 'reason']) string(defeat[field], `${observation.product_id} defeat.${field}`);
      if (!['out_of_scope', 'looked_and_blocked', 'authority_cannot_express'].includes(defeat.kind)) throw new Error(`${observation.product_id} has an unknown defeat kind`);
      if (defeat.impact !== 'disjoint' || !rejected.has(defeat.affects)) throw new Error(`${observation.product_id} has a blocking or unscoped defeat`);
    }
  }
}

function verifyConcreteProjections(behavior) {
  const products = [];
  for (const observation of behavior.observations) {
    const projection = observation.activity_projection;
    assertObject(projection, `${observation.product_id} activity_projection`);
    if (!Array.isArray(projection.scope_refs) || projection.scope_refs.length === 0) throw new Error(`${observation.product_id} projection has no scope`);
    if (projection.extent !== 'full') throw new Error(`${observation.product_id} verifier fixture must establish its exact selected scope`);
    if (!Array.isArray(projection.entries) || projection.entries.length !== observation.ordered_source_ids.length) throw new Error(`${observation.product_id} projection entry count differs from selector output`);
    const ids = projection.entries.map((entry, index) => {
      if (!Array.isArray(entry.source_refs) || entry.source_refs.length !== 1 || entry.projection_key !== undefined) throw new Error(`${observation.product_id} projection entry ${index} has no exact source join`);
      const reference = entry.source_refs[0];
      string(reference.namespace, `${observation.product_id} entry namespace`);
      string(reference.id, `${observation.product_id} entry id`);
      return reference.id;
    });
    if (JSON.stringify(ids) !== JSON.stringify(observation.ordered_source_ids)) throw new Error(`${observation.product_id} concrete projection reordered selector output`);
    for (const reference of projection.scope_refs) {
      string(reference.namespace, `${observation.product_id} scope namespace`);
      string(reference.id, `${observation.product_id} scope id`);
    }
    products.push(observation.product_id);
  }
  return products;
}

export async function liftCorpus(corpusRoot = defaultCorpusRoot()) {
  const root = path.resolve(corpusRoot);
  const lockBytes = await readFile(path.join(root, 'authorities.lock.json'));
  const lock = JSON.parse(lockBytes);
  validateLock(lock);
  const context = await createContext(root, lock);
  const observations = lock.products.map(product => PROJECT[product.projector](product, context));
  validateDefeats(observations);
  const behavior = runBehavioralCases(context);
  const verticalProducts = verifyConcreteProjections(behavior);
  return {
    protocol: OUTPUT_PROTOCOL,
    generator: {
      name: TOOL_NAME,
      version: TOOL_VERSION,
      implementation_paths: IMPLEMENTATION_PATHS,
      implementation_sha256: await implementationDigest(),
      package_lock_path: PACKAGE_LOCK_PATH,
      package_lock_sha256: sha256(await readFile(path.join(TOOL_ROOT, PACKAGE_LOCK_PATH))),
      authority_lock_sha256: sha256(lockBytes),
      parsers: {
        typescript: '@babel/parser@7.29.8',
        svelte: 'svelte/compiler@5.56.10',
        python: 'tree-sitter-python@0.23.6',
        rust: 'tree-sitter-rust@0.24.0',
        toml: 'smol-toml@1.8.0',
        behavior_transpiler: 'typescript@5.9.3',
      },
      evidence_kind: 'static_product_state_corroboration_plus_reviewed_exact_isolated_function_execution',
    },
    recurrence: {
      status: 'two_product_concrete_vertical_with_six_product_static_corroboration',
      declared_governance_groups: observations.map(observation => observation.governance_group),
      declared_ecosystems: observations.map(observation => observation.declared_ecosystem),
      contract_vertical: {
        contract: 'org.gooi.semantics.activity_projection/ordered_activity@0.1.0',
        products: verticalProducts,
        concrete_projection_count: verticalProducts.length,
      },
      rejected: REJECTED_CANDIDATES,
    },
    observations,
    behavior,
  };
}

export function encode(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}
