import {
  allNodes,
  evidence,
  functionNamed,
  isBoolean,
  isDirectCall,
  isIdentifier,
  isMethodCall,
  isString,
  jestCallCount,
  oneNode,
  testBody,
  variableNamed,
} from './ast.mjs';

const TEST = 'react_dom.simple_event_plugin.conformance';
const PLUGIN = 'react_dom.simple_event_plugin.runtime';
const DISPATCH = 'react_dom.dom_plugin_event_system.runtime';

export function liftReact(context) {
  // This React revision retains `@flow` headers while its runtime files use
  // TypeScript-style `as` assertions. The exact per-authority variants are
  // pinned in generator provenance; no source preprocessing is performed.
  const testAst = context.ast(TEST);
  const pluginAst = context.ast(PLUGIN);
  const dispatchAst = context.ast(DISPATCH);

  const positiveTest = testBody(
    testAst,
    'it',
    'A non-interactive tags click when disabled',
  );
  const element = variableNamed(positiveTest, 'element');
  const binding = oneNode(
    element.init,
    node =>
      node.type === 'JSXAttribute' &&
      node.name?.type === 'JSXIdentifier' &&
      node.name.name === 'onClick' &&
      node.value?.type === 'JSXExpressionContainer' &&
      isIdentifier(node.value.expression, 'onClick'),
    'React JSX onClick binding',
  );
  const helperUse = oneNode(
    positiveTest,
    node => {
      if (!isDirectCall(node, 'expectClickThru')) {
        return false;
      }
      const mounted = node.arguments[0]?.type === 'AwaitExpression'
        ? node.arguments[0].argument
        : node.arguments[0];
      return (
        isDirectCall(mounted, 'mounted') &&
        isIdentifier(mounted.arguments[0], 'element')
      );
    },
    'call connecting the bound React element to expectClickThru',
  );

  const helper = functionNamed(testAst, 'expectClickThru');
  if (!isIdentifier(helper.params[0], 'element')) {
    throw new Error('React expectClickThru no longer receives the mounted element');
  }
  const stimulus = oneNode(
    helper.body,
    node => isMethodCall(node, 'element', 'click') && node.arguments.length === 0,
    'React element.click stimulus',
  );
  const assertion = jestCallCount(helper.body, 'onClick', 1);

  const extraction = functionNamed(pluginAst, 'extractEvents');
  const clickSwitch = oneNode(
    extraction.body,
    node =>
      node.type === 'SwitchStatement' &&
      isIdentifier(node.discriminant, 'domEventName') &&
      node.cases.some(branch => isString(branch.test, 'click')),
    'React domEventName switch with a click branch',
  );
  const clickBranchIndex = clickSwitch.cases.findIndex(branch =>
    isString(branch.test, 'click'),
  );
  const mouseEventSelection = oneNode(
    clickSwitch,
    node =>
      node.type === 'AssignmentExpression' &&
      isIdentifier(node.left, 'SyntheticEventCtor') &&
      isIdentifier(node.right, 'SyntheticMouseEvent'),
    'React click-family SyntheticMouseEvent selection',
  );
  const mouseBranchIndex = clickSwitch.cases.findIndex(branch =>
    allNodes(branch, node => node === mouseEventSelection).length === 1,
  );
  if (
    clickBranchIndex < 0 ||
    mouseBranchIndex < clickBranchIndex ||
    clickSwitch.cases
      .slice(clickBranchIndex, mouseBranchIndex)
      .some(branch =>
        branch.consequent.some(statement => statement.type === 'BreakStatement'),
      )
  ) {
    throw new Error(
      'React click branch no longer falls through to SyntheticMouseEvent selection',
    );
  }
  const clickBranch = clickSwitch.cases[clickBranchIndex];
  const listenerAccumulation = oneNode(
    extraction.body,
    node =>
      isDirectCall(node, 'accumulateSinglePhaseListeners') &&
      isIdentifier(node.arguments[1], 'reactName') &&
      node.arguments[2]?.type === 'MemberExpression' &&
      isIdentifier(node.arguments[2].object, 'nativeEvent') &&
      isIdentifier(node.arguments[2].property, 'type'),
    'React listener accumulation from the mapped native event',
  );
  const queuedListeners = oneNode(
    extraction.body,
    node => {
      if (!isMethodCall(node, 'dispatchQueue', 'push')) {
        return false;
      }
      if (node.start <= listenerAccumulation.end) {
        return false;
      }
      const queued = node.arguments[0];
      return (
        queued?.type === 'ObjectExpression' &&
        queued.properties.some(
          property =>
            property.type === 'ObjectProperty' &&
            isIdentifier(property.key, 'event') &&
            isIdentifier(property.value, 'event'),
        ) &&
        queued.properties.some(
          property =>
            property.type === 'ObjectProperty' &&
            isIdentifier(property.key, 'listeners') &&
            isIdentifier(property.value, 'listeners'),
        )
      );
    },
    'React event/listeners dispatch queue insertion',
  );

  const processQueue = functionNamed(dispatchAst, 'processDispatchQueue');
  const queueForward = oneNode(
    processQueue.body,
    node =>
      isDirectCall(node, 'processDispatchQueueItemsInOrder') &&
      isIdentifier(node.arguments[0], 'event') &&
      isIdentifier(node.arguments[1], 'listeners'),
    'React queue entry forwarding',
  );
  const processItems = functionNamed(dispatchAst, 'processDispatchQueueItemsInOrder');
  const executeForward = allNodes(
    processItems.body,
    node =>
      isDirectCall(node, 'executeDispatch') &&
      isIdentifier(node.arguments[0], 'event') &&
      isIdentifier(node.arguments[1], 'listener') &&
      isIdentifier(node.arguments[2], 'currentTarget'),
  );
  if (executeForward.length !== 2) {
    throw new Error(
      `expected React capture and bubble executeDispatch paths; observed ${executeForward.length}`,
    );
  }
  const execute = functionNamed(dispatchAst, 'executeDispatch');
  const handlerInvocation = oneNode(
    execute.body,
    node =>
      isDirectCall(node, 'listener') &&
      node.arguments.length === 1 &&
      isIdentifier(node.arguments[0], 'event'),
    'React registered listener invocation',
  );

  const suppressedTest = testBody(
    testAst,
    'it',
    'does not register a click when clicking a child of a disabled element',
  );
  const disabled = oneNode(
    suppressedTest,
    node =>
      node.type === 'JSXAttribute' &&
      node.name?.type === 'JSXIdentifier' &&
      node.name.name === 'disabled' &&
      node.value?.type === 'JSXExpressionContainer' &&
      isBoolean(node.value.expression, true),
    'React disabled interactive binding',
  );
  const suppressedStimulus = oneNode(
    suppressedTest,
    node => isMethodCall(node, 'child', 'click'),
    'React click under a disabled interactive ancestor',
  );
  const suppressedAssertion = jestCallCount(
    suppressedTest,
    'onClick',
    0,
  );

  const auditSubject = 'react-dom:SimpleEventPlugin/onClick';
  return {
    audit_subject_id: auditSubject,
    authority_group: 'react_dom',
    ecosystem: 'react_dom',
    semantic: {
      action_id: auditSubject,
      outcome: 'invokes_registered_handler',
    },
    lineage: {
      runtime: 'react',
      participation: 'authority',
      evidence: [
        evidence(PLUGIN, extraction, {
          relation: 'defines_plugin_extractor',
          symbol: 'extractEvents',
        }),
        evidence(DISPATCH, execute, {
          relation: 'defines_dispatch_executor',
          symbol: 'executeDispatch',
        }),
      ],
    },
    chain: {
      binding: evidence(TEST, binding, {
        form: 'jsx_attribute',
        name: 'onClick',
        handler: 'onClick',
      }),
      stimulus: evidence(TEST, stimulus, {
        form: 'dom_element_click_method',
        receiver: 'element',
        method: 'click',
      }),
      assertion: evidence(TEST, assertion, {
        framework: 'jest',
        matcher: 'toHaveBeenCalledTimes',
        handler: 'onClick',
        expected_count: 1,
      }),
      test_link: evidence(TEST, helperUse, {
        binding_variable: 'element',
        mount_helper: 'mounted',
        assertion_helper: 'expectClickThru',
      }),
      runtime_accumulation: evidence(PLUGIN, listenerAccumulation, {
        mapped_listener_name: 'reactName',
        native_event_member: 'type',
      }),
      runtime_stimulus_mapping: evidence(PLUGIN, clickBranch, {
        discriminant: 'domEventName',
        event_name: 'click',
        fallthrough_event_constructor: 'SyntheticMouseEvent',
      }),
      runtime_event_construction: evidence(PLUGIN, mouseEventSelection, {
        assignment: 'SyntheticEventCtor',
        constructor: 'SyntheticMouseEvent',
      }),
      runtime_queue: evidence(PLUGIN, queuedListeners, {
        queue: 'dispatchQueue',
        fields: ['event', 'listeners'],
      }),
      runtime_queue_forward: evidence(DISPATCH, queueForward, {
        callee: 'processDispatchQueueItemsInOrder',
      }),
      runtime_handler_invocation: evidence(DISPATCH, handlerInvocation, {
        callee_parameter: 'listener',
        argument: 'event',
      }),
    },
    native: {
      host: 'browser_dom',
      binding_form: 'react_jsx_onClick_attribute',
      stimulus_form: 'dom_element_click_method',
      assertion_form: 'jest_mock_call_count',
      suppression: [
        {
          mechanism: 'disabled_interactive_ancestor',
          binding: evidence(TEST, disabled),
          stimulus: evidence(TEST, suppressedStimulus),
          assertion: evidence(TEST, suppressedAssertion, {
            matcher: 'toHaveBeenCalledTimes',
            expected_count: 0,
          }),
        },
      ],
    },
    sources: context.sourceReferences([PLUGIN, DISPATCH, TEST]),
    defeats: context.staticDefeats('react_dom'),
  };
}
