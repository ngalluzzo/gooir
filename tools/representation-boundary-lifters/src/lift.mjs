import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { babelParserConfigurations, inventoryBabel } from './babel.mjs';
import { sha256 } from './evidence.mjs';
import { inventoryVueSfc, vueParserConfiguration } from './vue.mjs';

export const LOCK_PROTOCOL = 'org.gooi.fixture.representation_boundaries/v1';
export const OUTPUT_PROTOCOL =
  'org.gooi.fixture.representation_boundary_native_observations/v1';

const TOOL_NAME = '@gooir/representation-boundary-lifters';
const TOOL_VERSION = '0.1.0';
const TOOL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const PACKAGE_LOCK_PATH = 'package-lock.json';
const IMPLEMENTATION_PATHS = Object.freeze([
  'package.json',
  'src/babel.mjs',
  'src/cli.mjs',
  'src/evidence.mjs',
  'src/lift.mjs',
  'src/refresh.mjs',
  'src/vue.mjs',
]);
const PRODUCT_FIELDS = new Set([
  'id',
  'governance_group',
  'lifecycle',
  'declared_ecosystem',
]);
const AUTHORITY_FIELDS = new Set([
  'id',
  'product_id',
  'role',
  'parser_variant',
  'repository',
  'source_path',
  'snapshot_path',
  'sha256',
  'license_snapshot',
]);
const LICENSE_FIELDS = new Set([
  'id',
  'product_id',
  'repository',
  'source_path',
  'snapshot_path',
  'sha256',
]);
const REPOSITORY_FIELDS = new Set(['url', 'commit']);
const PARSER_VARIANTS = new Set(['typescript_jsx', 'typescript', 'vue_sfc', 'json', 'html']);
const LIFECYCLES = new Set(['current', 'historical']);
const ARTIFACT_ROLES = new Set([
  'manifest',
  'native_source',
  'application_source',
  'type_source',
  'state_source',
  'provider_configuration_source',
  'registry_configuration',
  'materialized_source',
  'runtime_bridge_source',
  'export_source',
  'host_source',
]);
const FORBIDDEN_VERDICT_FIELDS = new Set(['establishes', 'defeats', 'semantic']);

function assertObject(value, subject) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${subject} must be an object`);
  }
}

function assertExactFields(value, expected, subject) {
  assertObject(value, subject);
  const actual = Object.keys(value);
  for (const key of actual) {
    if (!expected.has(key)) throw new Error(`${subject} has unknown field ${key}`);
  }
  for (const key of expected) {
    if (!Object.hasOwn(value, key)) throw new Error(`${subject} is missing field ${key}`);
  }
}

function rejectSemanticVerdicts(value, subject = 'lock') {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectSemanticVerdicts(item, `${subject}[${index}]`));
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_VERDICT_FIELDS.has(key)) {
      throw new Error(`${subject} contains prohibited authored verdict field ${key}`);
    }
    rejectSemanticVerdicts(child, `${subject}.${key}`);
  }
}

function requireString(value, subject) {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
    throw new Error(`${subject} must be a nonempty, trimmed string`);
  }
  return value;
}

function requireDigest(value, subject, length) {
  requireString(value, subject);
  if (!new RegExp(`^[0-9a-f]{${length}}$`).test(value)) {
    throw new Error(`${subject} must be ${length} lowercase hexadecimal characters`);
  }
}

function requireSafePath(value, subject) {
  requireString(value, subject);
  if (
    value.includes('\\') ||
    value.includes(':') ||
    value.includes('\0') ||
    path.posix.isAbsolute(value) ||
    value.split('/').some((part) => part === '' || part === '.' || part === '..') ||
    path.posix.normalize(value) !== value
  ) {
    throw new Error(`${subject} must be a safe normalized relative POSIX path`);
  }
}

function validateRepository(repository, subject) {
  assertExactFields(repository, REPOSITORY_FIELDS, subject);
  const url = requireString(repository.url, `${subject}.url`);
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${subject}.url must be an absolute URL`);
  }
  if (parsed.protocol !== 'https:') throw new Error(`${subject}.url must use https`);
  requireDigest(repository.commit, `${subject}.commit`, 40);
}

function unique(values, subject) {
  const seen = new Set();
  for (const value of values) {
    if (seen.has(value)) throw new Error(`${subject} contains duplicate ${value}`);
    seen.add(value);
  }
}

export function validateLockShape(lock) {
  assertExactFields(lock, new Set(['protocol', 'products', 'authorities', 'licenses']), 'lock');
  rejectSemanticVerdicts(lock);
  if (lock.protocol !== LOCK_PROTOCOL) throw new Error(`unsupported lock protocol ${lock.protocol}`);
  for (const name of ['products', 'authorities', 'licenses']) {
    if (!Array.isArray(lock[name])) throw new Error(`lock.${name} must be an array`);
  }
  if (lock.products.length === 0) throw new Error('lock.products must not be empty');
  if (lock.authorities.length === 0) throw new Error('lock.authorities must not be empty');
  if (lock.licenses.length === 0) throw new Error('lock.licenses must not be empty');

  lock.products.forEach((product, index) => {
    const subject = `lock.products[${index}]`;
    assertExactFields(product, PRODUCT_FIELDS, subject);
    requireString(product.id, `${subject}.id`);
    requireString(product.governance_group, `${subject}.governance_group`);
    requireString(product.declared_ecosystem, `${subject}.declared_ecosystem`);
    if (!LIFECYCLES.has(product.lifecycle)) {
      throw new Error(`${subject}.lifecycle must be current or historical`);
    }
  });
  unique(
    lock.products.map((product) => product.id),
    'product ids',
  );

  lock.authorities.forEach((authority, index) => {
    const subject = `lock.authorities[${index}]`;
    assertExactFields(authority, AUTHORITY_FIELDS, subject);
    requireString(authority.id, `${subject}.id`);
    requireString(authority.product_id, `${subject}.product_id`);
    requireString(authority.role, `${subject}.role`);
    if (!ARTIFACT_ROLES.has(authority.role)) {
      throw new Error(`${subject}.role is not a neutral artifact class`);
    }
    if (!PARSER_VARIANTS.has(authority.parser_variant)) {
      throw new Error(`${subject}.parser_variant is unsupported`);
    }
    validateRepository(authority.repository, `${subject}.repository`);
    requireSafePath(authority.source_path, `${subject}.source_path`);
    requireSafePath(authority.snapshot_path, `${subject}.snapshot_path`);
    requireDigest(authority.sha256, `${subject}.sha256`, 64);
    requireSafePath(authority.license_snapshot, `${subject}.license_snapshot`);
  });
  unique(
    lock.authorities.map((authority) => authority.id),
    'authority ids',
  );

  lock.licenses.forEach((license, index) => {
    const subject = `lock.licenses[${index}]`;
    assertExactFields(license, LICENSE_FIELDS, subject);
    requireString(license.id, `${subject}.id`);
    requireString(license.product_id, `${subject}.product_id`);
    validateRepository(license.repository, `${subject}.repository`);
    requireSafePath(license.source_path, `${subject}.source_path`);
    requireSafePath(license.snapshot_path, `${subject}.snapshot_path`);
    requireDigest(license.sha256, `${subject}.sha256`, 64);
  });
  unique(
    lock.licenses.map((license) => license.id),
    'license ids',
  );
  unique(
    [...lock.authorities, ...lock.licenses].map((entry) => entry.snapshot_path),
    'snapshot paths',
  );

  const products = new Set(lock.products.map((product) => product.id));
  for (const authority of lock.authorities) {
    if (!products.has(authority.product_id)) {
      throw new Error(`authority ${authority.id} references unknown product ${authority.product_id}`);
    }
    const license = lock.licenses.find(
      (candidate) =>
        candidate.product_id === authority.product_id &&
        candidate.snapshot_path === authority.license_snapshot,
    );
    if (!license) {
      throw new Error(
        `authority ${authority.id} has no same-product license ${authority.license_snapshot}`,
      );
    }
    if (
      license.repository.url !== authority.repository.url ||
      license.repository.commit !== authority.repository.commit
    ) {
      throw new Error(`authority ${authority.id} license repository/revision does not match`);
    }
  }
  for (const license of lock.licenses) {
    if (!products.has(license.product_id)) {
      throw new Error(`license ${license.id} references unknown product ${license.product_id}`);
    }
  }
  for (const product of lock.products) {
    if (!lock.authorities.some((authority) => authority.product_id === product.id)) {
      throw new Error(`product ${product.id} has no authority`);
    }
    if (!lock.licenses.some((license) => license.product_id === product.id)) {
      throw new Error(`product ${product.id} has no license`);
    }
  }
}

async function verifiedSnapshot(lockDirectory, entry) {
  const filename = path.resolve(lockDirectory, entry.snapshot_path);
  const relative = path.relative(lockDirectory, filename);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`snapshot ${entry.snapshot_path} escapes lock directory`);
  }
  let bytes;
  try {
    bytes = await readFile(filename);
  } catch (error) {
    throw new Error(`cannot read snapshot ${entry.snapshot_path}: ${error.message}`, {
      cause: error,
    });
  }
  const actual = sha256(bytes);
  if (actual !== entry.sha256) {
    throw new Error(`snapshot digest mismatch for ${entry.snapshot_path}`);
  }
  return bytes;
}

function inventoryJson(authority, source) {
  let value;
  try {
    value = JSON.parse(source);
  } catch (error) {
    throw new Error(`JSON parser rejected ${authority.id}: ${error.message}`, { cause: error });
  }
  const keys = [];
  const visit = (current, segments) => {
    if (Array.isArray(current)) {
      current.forEach((item, index) => visit(item, [...segments, index]));
      return;
    }
    if (!current || typeof current !== 'object') return;
    for (const key of Object.keys(current).sort()) {
      keys.push({ key, path: [...segments, key] });
      visit(current[key], [...segments, key]);
    }
  };
  visit(value, []);
  return {
    kind: 'json',
    parsed: true,
    root_type: Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value,
    counts: { keys: keys.length },
    keys,
  };
}

function inventoryHtml(source) {
  return {
    kind: 'html',
    parsed: false,
    byte_length: Buffer.byteLength(source, 'utf8'),
    reason: 'no authoritative HTML parser is pinned by this package',
  };
}

function inventory(authority, source) {
  if (authority.parser_variant === 'typescript_jsx' || authority.parser_variant === 'typescript') {
    return inventoryBabel(authority, source);
  }
  if (authority.parser_variant === 'vue_sfc') return inventoryVueSfc(authority, source);
  if (authority.parser_variant === 'json') return inventoryJson(authority, source);
  if (authority.parser_variant === 'html') return inventoryHtml(source);
  throw new Error(`unsupported parser variant ${authority.parser_variant}`);
}

function decodeSource(bytes, authorityId) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error(`snapshot for ${authorityId} is not valid UTF-8`, { cause: error });
  }
}

function emptySummary() {
  return {
    authority_count: 0,
    parser_variants: {
      typescript_jsx: 0,
      typescript: 0,
      vue_sfc: 0,
      json: 0,
      html: 0,
    },
    babel: {
      imports: 0,
      exports: 0,
      jsx_tags: 0,
      jsx_fragments: 0,
      jsx_conditionals: 0,
      jsx_iterations: 0,
      return_nulls: 0,
      native_events: 0,
    },
    vue_sfc: {
      blocks: 0,
      template_roots: 0,
      tags: 0,
      directives: 0,
      interpolations: 0,
      dynamic_components: 0,
      router_views: 0,
      teleports: 0,
    },
    json: { files: 0, keys: 0 },
    html: { files: 0, parsed_files: 0 },
  };
}

function summarize(authorities) {
  const summary = emptySummary();
  for (const authority of authorities) {
    summary.authority_count += 1;
    summary.parser_variants[authority.parser_variant] += 1;
    const native = authority.native;
    if (native.kind === 'babel') {
      for (const key of Object.keys(summary.babel)) summary.babel[key] += native.counts[key];
    } else if (native.kind === 'vue_sfc') {
      for (const key of Object.keys(summary.vue_sfc)) summary.vue_sfc[key] += native.counts[key];
    } else if (native.kind === 'json') {
      summary.json.files += 1;
      summary.json.keys += native.counts.keys;
    } else if (native.kind === 'html') {
      summary.html.files += 1;
      if (native.parsed) summary.html.parsed_files += 1;
    }
  }
  return summary;
}

async function implementationPin() {
  const hashParts = [];
  for (const implementationPath of IMPLEMENTATION_PATHS) {
    const bytes = await readFile(path.join(TOOL_ROOT, implementationPath));
    hashParts.push(Buffer.from(implementationPath, 'utf8'), Buffer.from([0]), bytes, Buffer.from([0]));
  }
  const packageLock = await readFile(path.join(TOOL_ROOT, PACKAGE_LOCK_PATH));
  return {
    implementation_paths: [...IMPLEMENTATION_PATHS],
    implementation_sha256: sha256(Buffer.concat(hashParts)),
    package_lock_path: PACKAGE_LOCK_PATH,
    package_lock_sha256: sha256(packageLock),
  };
}

async function verifyParserVersions() {
  const expected = [
    ['@babel/parser', '7.29.8'],
    ['@vue/compiler-sfc', '3.5.24'],
    ['@vue/compiler-dom', '3.5.24'],
  ];
  for (const [packageName, version] of expected) {
    const manifestPath = require.resolve(`${packageName}/package.json`);
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    if (manifest.name !== packageName || manifest.version !== version) {
      throw new Error(
        `loaded parser ${packageName} has version ${manifest.version ?? 'unknown'}, expected ${version}`,
      );
    }
  }
}

export function encodeProjection(projection) {
  return `${JSON.stringify(projection, null, 2)}\n`;
}

export async function liftLock(lockPath) {
  await verifyParserVersions();
  const absoluteLockPath = path.resolve(lockPath);
  const lockDirectory = path.dirname(absoluteLockPath);
  const lockBytes = await readFile(absoluteLockPath);
  let lock;
  try {
    lock = JSON.parse(lockBytes.toString('utf8'));
  } catch (error) {
    throw new Error(`lock is not valid JSON: ${error.message}`, { cause: error });
  }
  validateLockShape(lock);

  await Promise.all(lock.licenses.map((license) => verifiedSnapshot(lockDirectory, license)));
  const liftedAuthorities = await Promise.all(
    lock.authorities.map(async (authority) => {
      const sourceBytes = await verifiedSnapshot(lockDirectory, authority);
      const source = decodeSource(sourceBytes, authority.id);
      return {
        authority_id: authority.id,
        role: authority.role,
        parser_variant: authority.parser_variant,
        source: {
          repository: authority.repository,
          source_path: authority.source_path,
          snapshot_path: authority.snapshot_path,
          sha256: authority.sha256,
          license_snapshot: authority.license_snapshot,
        },
        native: inventory(authority, source),
      };
    }),
  );

  const pin = await implementationPin();
  const products = [...lock.products]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((product) => {
      const authorities = liftedAuthorities
        .filter((authority) => {
          const original = lock.authorities.find((candidate) => candidate.id === authority.authority_id);
          return original.product_id === product.id;
        })
        .sort((left, right) => left.authority_id.localeCompare(right.authority_id));
      return {
        product_id: product.id,
        governance_group: product.governance_group,
        lifecycle: product.lifecycle,
        declared_ecosystem: product.declared_ecosystem,
        summary: summarize(authorities),
        authorities,
      };
    });

  return {
    protocol: OUTPUT_PROTOCOL,
    generator: {
      name: TOOL_NAME,
      version: TOOL_VERSION,
      ...pin,
      parsers: {
        babel: {
          package: '@babel/parser',
          version: '7.29.8',
          configurations: babelParserConfigurations,
        },
        vue_sfc: {
          package: '@vue/compiler-sfc',
          version: '3.5.24',
          configuration: vueParserConfiguration.sfc,
        },
        vue_template: {
          package: '@vue/compiler-dom',
          version: '3.5.24',
          configuration: vueParserConfiguration.template,
        },
      },
      authority_lock_sha256: sha256(lockBytes),
    },
    products,
  };
}

export const lockSchema = Object.freeze({
  product_fields: [...PRODUCT_FIELDS],
  authority_fields: [...AUTHORITY_FIELDS],
  license_fields: [...LICENSE_FIELDS],
  artifact_roles: [...ARTIFACT_ROLES],
});
