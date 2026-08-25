import { parse } from '@babel/parser';

import { sortBySpan, sourceEvidence } from './evidence.mjs';

const PARSER_PLUGINS = Object.freeze({
  typescript_jsx: ['typescript', 'jsx'],
  typescript: ['typescript'],
});

function childNodes(node) {
  const children = [];
  for (const [key, value] of Object.entries(node)) {
    if (
      key === 'loc' ||
      key === 'start' ||
      key === 'end' ||
      key === 'extra' ||
      key === 'comments' ||
      key === 'tokens' ||
      key === 'errors'
    ) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item === 'object' && typeof item.type === 'string') {
          children.push(item);
        }
      }
    } else if (value && typeof value === 'object' && typeof value.type === 'string') {
      children.push(value);
    }
  }
  return children;
}

function walk(root, visitor) {
  const seen = new WeakSet();
  const visit = (node, parent) => {
    if (!node || typeof node !== 'object' || seen.has(node)) return;
    seen.add(node);
    visitor(node, parent);
    for (const child of childNodes(node)) visit(child, node);
  };
  visit(root, null);
}

function containsJsx(root) {
  let found = false;
  walk(root, (node) => {
    if (node.type === 'JSXElement' || node.type === 'JSXFragment') found = true;
  });
  return found;
}

function jsxName(node) {
  if (!node) return null;
  if (node.type === 'JSXIdentifier') return node.name;
  if (node.type === 'JSXNamespacedName') {
    return `${jsxName(node.namespace)}:${jsxName(node.name)}`;
  }
  if (node.type === 'JSXMemberExpression') {
    return `${jsxName(node.object)}.${jsxName(node.property)}`;
  }
  return null;
}

function tagType(nameNode, name) {
  if (nameNode.type === 'JSXNamespacedName') return 'namespaced';
  if (nameNode.type === 'JSXMemberExpression') return 'member';
  return /^[a-z]/.test(name) || name.includes('-') ? 'intrinsic' : 'component';
}

function evidence(authorityId, node, source) {
  return sourceEvidence(authorityId, node.type, node.start, node.end, source);
}

function jsxReturningCallback(call) {
  const callback = call.arguments?.[0];
  return callback && containsJsx(callback) ? callback : null;
}

export function inventoryBabel(authority, source) {
  const plugins = PARSER_PLUGINS[authority.parser_variant];
  if (!plugins) throw new Error(`unsupported Babel parser variant ${authority.parser_variant}`);

  let ast;
  try {
    ast = parse(source, {
      sourceType: 'unambiguous',
      errorRecovery: false,
      plugins,
    });
  } catch (error) {
    throw new Error(`Babel rejected ${authority.id}: ${error.message}`, { cause: error });
  }

  const imports = [];
  const exports = [];
  const jsxTags = [];
  const jsxFragments = [];
  const jsxConditionals = [];
  const jsxIterations = [];
  const returnNulls = [];
  const nativeEvents = [];

  walk(ast.program, (node) => {
    if (node.type === 'ImportDeclaration') {
      imports.push({
        kind: 'static',
        module: node.source.value,
        import_kind: node.importKind ?? 'value',
        evidence: evidence(authority.id, node, source),
      });
    } else if (node.type === 'CallExpression' && node.callee?.type === 'Import') {
      const module = node.arguments?.[0]?.type === 'StringLiteral' ? node.arguments[0].value : null;
      imports.push({
        kind: 'dynamic',
        module,
        import_kind: 'value',
        evidence: evidence(authority.id, node, source),
      });
    }

    if (
      node.type === 'ExportNamedDeclaration' ||
      node.type === 'ExportDefaultDeclaration' ||
      node.type === 'ExportAllDeclaration'
    ) {
      exports.push({
        kind:
          node.type === 'ExportNamedDeclaration'
            ? 'named'
            : node.type === 'ExportDefaultDeclaration'
              ? 'default'
              : 'all',
        source_module: node.source?.value ?? null,
        declaration_type: node.declaration?.type ?? null,
        evidence: evidence(authority.id, node, source),
      });
    }

    if (node.type === 'JSXElement') {
      const opening = node.openingElement;
      const name = jsxName(opening.name);
      const type = tagType(opening.name, name);
      jsxTags.push({
        name,
        tag_type: type,
        evidence: evidence(authority.id, opening, source),
      });

      if (type === 'intrinsic') {
        for (const attribute of opening.attributes) {
          if (
            attribute.type === 'JSXAttribute' &&
            attribute.name.type === 'JSXIdentifier' &&
            /^on[A-Z]/.test(attribute.name.name)
          ) {
            nativeEvents.push({
              tag: name,
              attribute: attribute.name.name,
              evidence: evidence(authority.id, attribute, source),
            });
          }
        }
      }
    } else if (node.type === 'JSXFragment') {
      jsxFragments.push({ evidence: evidence(authority.id, node, source) });
    } else if (
      (node.type === 'ConditionalExpression' || node.type === 'LogicalExpression') &&
      containsJsx(node)
    ) {
      jsxConditionals.push({
        operator: node.type === 'LogicalExpression' ? node.operator : '?:',
        evidence: evidence(authority.id, node, source),
      });
    } else if (
      node.type === 'CallExpression' &&
      node.callee?.type === 'MemberExpression' &&
      !node.callee.computed &&
      node.callee.property?.type === 'Identifier' &&
      node.callee.property.name === 'map'
    ) {
      const callback = jsxReturningCallback(node);
      if (callback) {
        jsxIterations.push({
          method: 'map',
          evidence: evidence(authority.id, node, source),
        });
      }
    } else if (node.type === 'ReturnStatement' && node.argument?.type === 'NullLiteral') {
      returnNulls.push({ evidence: evidence(authority.id, node, source) });
    }
  });

  const collections = {
    imports: sortBySpan(imports),
    exports: sortBySpan(exports),
    jsx_tags: sortBySpan(jsxTags),
    jsx_fragments: sortBySpan(jsxFragments),
    jsx_conditionals: sortBySpan(jsxConditionals),
    jsx_iterations: sortBySpan(jsxIterations),
    return_nulls: sortBySpan(returnNulls),
    native_events: sortBySpan(nativeEvents),
  };

  return {
    kind: 'babel',
    parsed: true,
    parser_configuration: {
      source_type: 'unambiguous',
      error_recovery: false,
      plugins,
    },
    counts: Object.fromEntries(
      Object.entries(collections).map(([name, items]) => [name, items.length]),
    ),
    ...collections,
  };
}

export const babelParserConfigurations = Object.freeze({
  typescript_jsx: {
    source_type: 'unambiguous',
    error_recovery: false,
    plugins: ['typescript', 'jsx'],
  },
  typescript: {
    source_type: 'unambiguous',
    error_recovery: false,
    plugins: ['typescript'],
  },
});
