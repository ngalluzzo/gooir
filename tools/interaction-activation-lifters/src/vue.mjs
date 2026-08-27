import {
  allNodes,
  evidence,
  functionNamed,
  isDirectCall,
  isIdentifier,
  isMethodCall,
  isString,
  jestCallCount,
  oneNode,
  testBody,
} from './ast.mjs';

const RUNTIME = 'vue_runtime_dom.events.runtime';
const TEST = 'vue_runtime_dom.patch_events.conformance';

export function liftVue(context) {
  const runtimeAst = context.ast(RUNTIME);
  const testAst = context.ast(TEST);

  const positiveTest = testBody(testAst, 'it', 'should assign event handler');
  const binding = oneNode(
    positiveTest,
    node =>
      isDirectCall(node, 'patchProp') &&
      isIdentifier(node.arguments[0], 'el') &&
      isString(node.arguments[1], 'onClick') &&
      node.arguments[2]?.type === 'NullLiteral' &&
      isIdentifier(node.arguments[3], 'fn'),
    'Vue patchProp event binding',
  );
  const stimuli = allNodes(
    positiveTest,
    node =>
      isMethodCall(node, 'el', 'dispatchEvent') &&
      node.arguments[0]?.type === 'NewExpression' &&
      isIdentifier(node.arguments[0].callee, 'Event') &&
      isString(node.arguments[0].arguments[0], 'click'),
  );
  if (stimuli.length !== 3) {
    throw new Error(
      `expected three Vue click dispatches before the positive assertion; observed ${stimuli.length}`,
    );
  }
  const assertion = jestCallCount(positiveTest, 'fn', 3);

  const patchEvent = functionNamed(runtimeAst, 'patchEvent');
  const createInvoker = oneNode(
    patchEvent.body,
    node =>
      isDirectCall(node, 'createInvoker') &&
      allNodes(node.arguments[0], child => isIdentifier(child, 'nextValue'))
        .length > 0,
    'Vue invoker construction from nextValue',
  );
  const installInvoker = oneNode(
    patchEvent.body,
    node =>
      isDirectCall(node, 'addEventListener') &&
      isIdentifier(node.arguments[0], 'el') &&
      isIdentifier(node.arguments[1], 'name') &&
      isIdentifier(node.arguments[2], 'invoker'),
    'Vue native listener installation',
  );
  const invokerFactory = functionNamed(runtimeAst, 'createInvoker');
  const handlerInvocation = oneNode(
    invokerFactory.body,
    node =>
      isDirectCall(node, 'callWithAsyncErrorHandling') &&
      isIdentifier(node.arguments[0], 'value') &&
      node.arguments[3]?.type === 'ArrayExpression' &&
      isIdentifier(node.arguments[3].elements[0], 'e'),
    'Vue scalar registered-handler invocation',
  );

  const suppressedTest = testBody(testAst, 'it', 'should unassign event handler');
  const removal = oneNode(
    suppressedTest,
    node =>
      isDirectCall(node, 'patchProp') &&
      isIdentifier(node.arguments[0], 'el') &&
      isString(node.arguments[1], 'onClick') &&
      isIdentifier(node.arguments[2], 'fn') &&
      node.arguments[3]?.type === 'NullLiteral',
    'Vue event-handler removal',
  );
  const suppressedStimulus = oneNode(
    suppressedTest,
    node =>
      isMethodCall(node, 'el', 'dispatchEvent') &&
      node.arguments[0]?.type === 'NewExpression' &&
      isIdentifier(node.arguments[0].callee, 'Event') &&
      isString(node.arguments[0].arguments[0], 'click'),
    'Vue dispatch after handler removal',
  );
  const suppressedAssertion = oneNode(
    suppressedTest,
    node => {
      if (
        node.type !== 'CallExpression' ||
        node.callee.type !== 'MemberExpression' ||
        node.callee.computed ||
        !isIdentifier(node.callee.property, 'toHaveBeenCalled')
      ) {
        return false;
      }
      const negation = node.callee.object;
      const expectation = negation?.type === 'MemberExpression'
        ? negation.object
        : undefined;
      return (
        negation?.computed === false &&
        isIdentifier(negation.property, 'not') &&
        expectation?.type === 'CallExpression' &&
        isIdentifier(expectation.callee, 'expect') &&
        isIdentifier(expectation.arguments[0], 'fn')
      );
    },
    'Vue negative handler assertion after removal',
  );

  const auditSubject = 'vue-runtime-dom:patchEvent/onClick';
  return {
    audit_subject_id: auditSubject,
    authority_group: 'vue_runtime_dom',
    ecosystem: 'vue_runtime_dom',
    semantic: {
      action_id: auditSubject,
      outcome: 'invokes_registered_handler',
    },
    lineage: {
      runtime: 'vue',
      participation: 'authority',
      evidence: [
        evidence(RUNTIME, patchEvent, {
          relation: 'defines_runtime_event_patch',
          symbol: 'patchEvent',
        }),
        evidence(RUNTIME, handlerInvocation, {
          relation: 'invokes_runtime_handler',
          symbol: 'callWithAsyncErrorHandling',
        }),
      ],
    },
    chain: {
      binding: evidence(TEST, binding, {
        form: 'patchProp',
        event_prop: 'onClick',
        handler: 'fn',
      }),
      stimulus: evidence(TEST, stimuli[0], {
        form: 'dispatchEvent',
        event_constructor: 'Event',
        event_name: 'click',
        observed_dispatch_count: 3,
      }),
      assertion: evidence(TEST, assertion, {
        framework: 'vitest',
        matcher: 'toHaveBeenCalledTimes',
        handler: 'fn',
        expected_count: 3,
      }),
      runtime_binding: evidence(RUNTIME, createInvoker, {
        callee: 'createInvoker',
        handler_source: 'nextValue',
      }),
      runtime_installation: evidence(RUNTIME, installInvoker, {
        callee: 'addEventListener',
        listener: 'invoker',
      }),
      runtime_handler_invocation: evidence(RUNTIME, handlerInvocation, {
        callee: 'callWithAsyncErrorHandling',
        handler: 'value',
        event_argument: 'e',
      }),
    },
    native: {
      host: 'browser_dom',
      binding_form: 'vue_runtime_dom_patchProp',
      stimulus_form: 'dom_dispatchEvent',
      assertion_form: 'vitest_mock_call_count',
      suppression: [
        {
          mechanism: 'patchProp_handler_removal',
          binding: evidence(TEST, removal),
          stimulus: evidence(TEST, suppressedStimulus),
          assertion: evidence(TEST, suppressedAssertion, {
            matcher: 'not.toHaveBeenCalled',
          }),
        },
      ],
    },
    sources: context.sourceReferences([RUNTIME, TEST]),
    defeats: context.staticDefeats('vue_runtime_dom'),
  };
}
