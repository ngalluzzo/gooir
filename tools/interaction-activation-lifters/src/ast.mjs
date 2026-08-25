import {parse} from '@babel/parser';

export function parseAuthority(source, language, sourcePath) {
  const plugins =
    language === 'flow_jsx' ? ['flow', 'jsx'] : ['typescript', 'jsx'];

  try {
    return parse(source, {
      sourceType: 'unambiguous',
      sourceFilename: sourcePath,
      plugins,
      errorRecovery: false,
    });
  } catch (error) {
    throw new Error(`could not parse ${sourcePath}: ${error.message}`, {
      cause: error,
    });
  }
}

export function allNodes(root, predicate) {
  const matches = [];
  walk(root, node => {
    if (predicate(node)) {
      matches.push(node);
    }
  });
  return matches;
}

export function oneNode(root, predicate, description) {
  const matches = allNodes(root, predicate);
  if (matches.length !== 1) {
    throw new Error(
      `expected exactly one ${description}; observed ${matches.length}`,
    );
  }
  return matches[0];
}

export function walk(root, visit) {
  const pending = [root];
  while (pending.length > 0) {
    const value = pending.pop();
    if (!value || typeof value !== 'object') {
      continue;
    }
    if (typeof value.type === 'string') {
      visit(value);
    }
    for (const [key, child] of Object.entries(value)) {
      if (
        key === 'loc' ||
        key === 'start' ||
        key === 'end' ||
        key === 'extra' ||
        key === 'errors'
      ) {
        continue;
      }
      if (Array.isArray(child)) {
        for (let index = child.length - 1; index >= 0; index -= 1) {
          pending.push(child[index]);
        }
      } else {
        pending.push(child);
      }
    }
  }
}

export function isIdentifier(node, name) {
  return node?.type === 'Identifier' && node.name === name;
}

export function isString(node, value) {
  return node?.type === 'StringLiteral' && node.value === value;
}

export function isNumber(node, value) {
  return node?.type === 'NumericLiteral' && node.value === value;
}

export function isBoolean(node, value) {
  return node?.type === 'BooleanLiteral' && node.value === value;
}

export function memberParts(node) {
  if (node?.type !== 'MemberExpression' || node.computed) {
    return undefined;
  }
  if (node.object.type === 'Identifier' && node.property.type === 'Identifier') {
    return [node.object.name, node.property.name];
  }
  return undefined;
}

export function isDirectCall(node, name) {
  return node?.type === 'CallExpression' && isIdentifier(node.callee, name);
}

export function isMethodCall(node, receiver, method) {
  if (node?.type !== 'CallExpression') {
    return false;
  }
  const parts = memberParts(node.callee);
  return parts?.[0] === receiver && parts?.[1] === method;
}

export function functionNamed(ast, name) {
  return oneNode(
    ast,
    node =>
      node.type === 'FunctionDeclaration' && isIdentifier(node.id, name),
    `function declaration ${name}`,
  );
}

export function variableNamed(root, name) {
  return oneNode(
    root,
    node =>
      node.type === 'VariableDeclarator' && isIdentifier(node.id, name),
    `variable declaration ${name}`,
  );
}

export function testBody(ast, runner, title) {
  const testCall = oneNode(
    ast,
    node => {
      if (node.type !== 'CallExpression' || !isString(node.arguments[0], title)) {
        return false;
      }
      if (isIdentifier(node.callee, runner)) {
        return true;
      }
      return (
        node.callee.type === 'MemberExpression' &&
        !node.callee.computed &&
        isIdentifier(node.callee.object, runner) &&
        node.callee.property.type === 'Identifier'
      );
    },
    `${runner} declaration ${JSON.stringify(title)}`,
  );
  const callback = testCall.arguments[1];
  if (
    callback?.type !== 'FunctionExpression' &&
    callback?.type !== 'ArrowFunctionExpression'
  ) {
    throw new Error(`${title} does not have a function test body`);
  }
  return callback;
}

export function jestCallCount(root, handler, expectedCount, negated = false) {
  return oneNode(
    root,
    node => {
      if (
        node.type !== 'CallExpression' ||
        !isNumber(node.arguments[0], expectedCount) ||
        node.callee.type !== 'MemberExpression' ||
        node.callee.computed ||
        !isIdentifier(node.callee.property, 'toHaveBeenCalledTimes')
      ) {
        return false;
      }
      let expectation = node.callee.object;
      if (negated) {
        if (
          expectation.type !== 'MemberExpression' ||
          expectation.computed ||
          !isIdentifier(expectation.property, 'not')
        ) {
          return false;
        }
        expectation = expectation.object;
      }
      return (
        expectation.type === 'CallExpression' &&
        isIdentifier(expectation.callee, 'expect') &&
        isIdentifier(expectation.arguments[0], handler)
      );
    },
    `${negated ? 'negative' : 'positive'} call-count assertion for ${handler}`,
  );
}

export function evidence(source, node, fields = {}) {
  if (!node?.loc) {
    throw new Error(`AST node in ${source} has no source location`);
  }
  return {
    source,
    node_type: node.type,
    loc: {
      start: {line: node.loc.start.line, column: node.loc.start.column},
      end: {line: node.loc.end.line, column: node.loc.end.column},
    },
    span: {
      utf16: {start: node.start, end: node.end},
    },
    ...fields,
  };
}
