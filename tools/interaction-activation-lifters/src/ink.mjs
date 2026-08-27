import {
  allNodes,
  evidence,
  isBoolean,
  isDirectCall,
  isIdentifier,
  isMethodCall,
  isString,
  oneNode,
  testBody,
  variableNamed,
} from './ast.mjs';

const RUNTIME = 'ink.use_input.runtime';
const RECONCILER = 'ink.reconciler.runtime';
const TEST = 'ink.use_input.conformance';
const FIXTURE = 'ink.use_input_multiple.fixture';

function avaOutputAssertion(root, assertion, expectedOutput) {
  return oneNode(
    root,
    node => {
      if (!isMethodCall(node, 't', assertion)) {
        return false;
      }
      const includes = node.arguments[0];
      if (
        includes?.type !== 'CallExpression' ||
        includes.callee.type !== 'MemberExpression' ||
        includes.callee.computed ||
        !isIdentifier(includes.callee.property, 'includes') ||
        !isString(includes.arguments[0], expectedOutput)
      ) {
        return false;
      }
      const output = includes.callee.object;
      return (
        output.type === 'MemberExpression' &&
        !output.computed &&
        isIdentifier(output.object, 'ps') &&
        isIdentifier(output.property, 'output')
      );
    },
    `Ink AVA ${assertion} output assertion for ${JSON.stringify(expectedOutput)}`,
  );
}

export function liftInk(context) {
  const runtimeAst = context.ast(RUNTIME);
  const reconcilerAst = context.ast(RECONCILER);
  const testAst = context.ast(TEST);
  const fixtureAst = context.ast(FIXTURE);

  const useInput = variableNamed(runtimeAst, 'useInput');
  const localReconcilerImport = oneNode(
    runtimeAst,
    node =>
      node.type === 'ImportDeclaration' &&
      isString(node.source, '../reconciler.js') &&
      node.specifiers.some(
        specifier =>
          specifier.type === 'ImportDefaultSpecifier' &&
          isIdentifier(specifier.local, 'reconciler'),
      ),
    'Ink use-input local reconciler import',
  );
  const reactReconcilerImport = oneNode(
    reconcilerAst,
    node =>
      node.type === 'ImportDeclaration' &&
      isString(node.source, 'react-reconciler') &&
      node.specifiers.some(
        specifier =>
          specifier.type === 'ImportDefaultSpecifier' &&
          isIdentifier(specifier.local, 'createReconciler'),
      ),
    'Ink react-reconciler import',
  );
  const reactRuntimeImport = oneNode(
    reconcilerAst,
    node =>
      node.type === 'ImportDeclaration' &&
      isString(node.source, 'react') &&
      node.specifiers.some(
        specifier =>
          specifier.type === 'ImportSpecifier' &&
          isIdentifier(specifier.imported, 'createContext'),
      ) &&
      node.specifiers.some(
        specifier =>
          specifier.type === 'ImportSpecifier' &&
          isIdentifier(specifier.imported, 'version') &&
          isIdentifier(specifier.local, 'reactVersion'),
      ),
    'Ink React runtime import',
  );
  if (
    useInput.init?.type !== 'ArrowFunctionExpression' ||
    !isIdentifier(useInput.init.params[0], 'inputHandler')
  ) {
    throw new Error('Ink useInput no longer receives inputHandler as its first parameter');
  }
  const handleData = variableNamed(useInput.init.body, 'handleData');
  if (
    !isDirectCall(handleData.init, 'useEffectEvent') ||
    handleData.init.arguments[0]?.type !== 'ArrowFunctionExpression'
  ) {
    throw new Error('Ink handleData is no longer an effect-event callback');
  }
  const handlerInvocation = oneNode(
    handleData.init.arguments[0].body,
    node =>
      isDirectCall(node, 'inputHandler') &&
      isIdentifier(node.arguments[0], 'input') &&
      isIdentifier(node.arguments[1], 'key'),
    'Ink registered input-handler invocation',
  );
  const inputEffect = oneNode(
    useInput.init.body,
    node =>
      isDirectCall(node, 'useEffect') &&
      node.arguments[0]?.type === 'ArrowFunctionExpression' &&
      allNodes(
        node.arguments[0].body,
        child =>
          child.type === 'CallExpression' &&
          child.callee.type === 'MemberExpression' &&
          !child.callee.computed &&
          isIdentifier(child.callee.object, 'internal_eventEmitter') &&
          isIdentifier(child.callee.property, 'on') &&
          isString(child.arguments[0], 'input') &&
          isIdentifier(child.arguments[1], 'handleData'),
      ).length === 1,
    'Ink input subscription effect',
  );
  const subscription = oneNode(
    inputEffect.arguments[0].body,
    node =>
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      !node.callee.computed &&
      isIdentifier(node.callee.object, 'internal_eventEmitter') &&
      isIdentifier(node.callee.property, 'on') &&
      isString(node.arguments[0], 'input') &&
      isIdentifier(node.arguments[1], 'handleData'),
    'Ink internal input event subscription',
  );
  const inactiveGuard = oneNode(
    inputEffect.arguments[0].body,
    node =>
      node.type === 'IfStatement' &&
      node.test.type === 'BinaryExpression' &&
      node.test.operator === '===' &&
      node.test.left.type === 'MemberExpression' &&
      !node.test.left.computed &&
      isIdentifier(node.test.left.object, 'options') &&
      isIdentifier(node.test.left.property, 'isActive') &&
      isBoolean(node.test.right, false) &&
      node.consequent.type === 'BlockStatement' &&
      node.consequent.body.some(statement => statement.type === 'ReturnStatement'),
    'Ink inactive-hook subscription guard',
  );

  const activeBindings = allNodes(
    fixtureAst,
    node =>
      isDirectCall(node, 'useInput') &&
      isIdentifier(node.arguments[0], 'handleInput') &&
      node.arguments.length === 1,
  );
  if (activeBindings.length !== 1) {
    throw new Error(
      `expected one active Ink useInput binding; observed ${activeBindings.length}`,
    );
  }
  const inactiveBinding = oneNode(
    fixtureAst,
    node => {
      if (
        !isDirectCall(node, 'useInput') ||
        !isIdentifier(node.arguments[0], 'handleInput') ||
        node.arguments[1]?.type !== 'ObjectExpression'
      ) {
        return false;
      }
      return node.arguments[1].properties.some(
        property =>
          property.type === 'ObjectProperty' &&
          isIdentifier(property.key, 'isActive') &&
          isBoolean(property.value, false),
      );
    },
    'Ink inactive useInput binding',
  );
  const handleInput = variableNamed(fixtureAst, 'handleInput');
  const effect = oneNode(
    handleInput.init,
    node =>
      isDirectCall(node, 'setInput') &&
      node.arguments[0]?.type === 'ArrowFunctionExpression' &&
      node.arguments[0].body.type === 'BinaryExpression' &&
      node.arguments[0].body.operator === '+' &&
      isIdentifier(node.arguments[0].body.left, 'previousInput') &&
      isIdentifier(node.arguments[0].body.right, 'input'),
    'Ink handler state effect',
  );
  const renderedEffect = oneNode(
    fixtureAst,
    node =>
      node.type === 'JSXExpressionContainer' &&
      isIdentifier(node.expression, 'input') &&
      node.expression.loc?.start.line === node.loc?.start.line,
    'Ink rendered input state',
  );

  const conformance = testBody(
    testAst,
    'test',
    'useInput - ignore input if not active',
  );
  const fixtureLaunch = oneNode(
    conformance,
    node => isDirectCall(node, 'term') && isString(node.arguments[0], 'use-input-multiple'),
    'Ink PTY fixture launch',
  );
  const stimulus = oneNode(
    conformance,
    node => isMethodCall(node, 'ps', 'write') && isString(node.arguments[0], 'x'),
    'Ink PTY input stimulus',
  );
  const assertion = avaOutputAssertion(conformance, 'true', 'x');
  const suppressedAssertion = avaOutputAssertion(conformance, 'false', 'xx');

  const auditSubject = 'ink:useInput/input';
  return {
    audit_subject_id: auditSubject,
    authority_group: 'ink_terminal',
    ecosystem: 'ink',
    semantic: {
      action_id: auditSubject,
      outcome: 'invokes_registered_handler',
    },
    lineage: {
      runtime: 'react',
      participation: 'renderer',
      evidence: [
        evidence(RUNTIME, localReconcilerImport, {
          relation: 'imports_local_reconciler',
          module: '../reconciler.js',
          imported: 'default as reconciler',
        }),
        evidence(RECONCILER, reactReconcilerImport, {
          relation: 'imports_react_reconciler',
          module: 'react-reconciler',
          imported: 'default as createReconciler',
        }),
        evidence(RECONCILER, reactRuntimeImport, {
          relation: 'imports_react_runtime',
          module: 'react',
          imported: ['createContext', 'version as reactVersion'],
        }),
      ],
    },
    chain: {
      binding: evidence(FIXTURE, activeBindings[0], {
        form: 'useInput_hook',
        handler: 'handleInput',
        active_by_default: true,
      }),
      stimulus: evidence(TEST, stimulus, {
        form: 'pty_write',
        receiver: 'ps',
        input: 'x',
      }),
      assertion: evidence(TEST, assertion, {
        framework: 'ava',
        matcher: 'true(output.includes)',
        expected_output: 'x',
        observation: 'rendered_handler_effect',
      }),
      fixture_link: evidence(TEST, fixtureLaunch, {
        fixture: 'use-input-multiple',
      }),
      handler_effect: evidence(FIXTURE, effect, {
        state_setter: 'setInput',
        update: 'previousInput_plus_input',
      }),
      rendered_effect: evidence(FIXTURE, renderedEffect, {
        component: 'Text',
        expression: 'input',
      }),
      runtime_subscription: evidence(RUNTIME, subscription, {
        emitter: 'internal_eventEmitter',
        event: 'input',
        callback: 'handleData',
      }),
      runtime_handler_invocation: evidence(RUNTIME, handlerInvocation, {
        callee_parameter: 'inputHandler',
        arguments: ['input', 'key'],
      }),
    },
    native: {
      host: 'terminal_pty',
      binding_form: 'ink_useInput_hook',
      stimulus_form: 'pty_stdin_write',
      assertion_form: 'ava_rendered_output_inclusion',
      suppression: [
        {
          mechanism: 'isActive_false',
          binding: evidence(FIXTURE, inactiveBinding),
          runtime_guard: evidence(RUNTIME, inactiveGuard),
          assertion: evidence(TEST, suppressedAssertion, {
            matcher: 'false(output.includes)',
            excluded_output: 'xx',
          }),
        },
      ],
    },
    sources: context.sourceReferences([RUNTIME, RECONCILER, FIXTURE, TEST]),
    defeats: context.staticDefeats('ink_terminal'),
  };
}
