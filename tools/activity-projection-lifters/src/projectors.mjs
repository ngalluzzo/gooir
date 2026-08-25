import {byteEvidence, sha256, utf16Evidence} from './evidence.mjs';
import {
  executeExportedTypescript,
  findBabel,
} from './parsers.mjs';

function nameOf(node) {
  return node?.id?.name ?? node?.key?.name ?? node?.key?.value;
}

// These are semantic-review pins for the exact positive nodes, separate from
// the corpus lock. Relocking changed upstream bytes cannot silently authorize a
// new projection route; the source-specific projector must be reviewed too.
const REVIEWED_EVIDENCE = Object.freeze({
  lobe_chat: [
    '66dd9b4410c8b8aeb2d911b447cc85d71a191642dd84463f3939b97bed17ef05',
    '02356ad29fa15b92ede56d8063139baccd874433d707a93a64725009b06c17bb',
    'c1c8c17e78be0c19cf525b10de2807441ad54d53f9d3039ce34e7bb68c1abbbd',
    '27092626c014b08eef27aa76d3d6d68980dc156e259e69b986cbbff65c1a9d1e',
  ],
  libre_chat: [
    '2d701b91846d37e0bf0388ea9cbee577439a02f774249b84a35444677b074e16',
    '9ab468ae80120b3c66d5394b908e22e0b44edd1ecaf23b2a568f3150776bc774',
    'e8293b7722aa3c33210bf638c3f7081ebb07241815f39190343996773be22c03',
  ],
  open_webui: [
    '05371fffc097f7ddbd71d40f469c2c9d941c815cf78dc5f7b849a54820302473',
    'cc2308ebf6d4596b408e0a6b345e6daaef323277e6c41ac5bb2c606528d17f7d',
    'f1ad0ec6ec3c3a298adfc1f08bc9e3f129d36b6ff6c3f053b90bf67fff7fa5d7',
    'c5e8d735441d34b923b78b79ed2185ad194f2efdb8eb6814ae9a475271c2fd42',
  ],
  chat_ui: [
    '07086457fc8d76dc200e3d70c9dfc5a96d631553f315090fc42c4f86ca3d5f31',
    'ab277a1bcdf2d225600d44d56b74c3c89245d114c61114453c1cc094893f1510',
    'b1fda2e25af8bbbf0b394faa940d01ea4c334d07e97e9fa00164f11f4fc6473b',
  ],
  gemini_cli: [
    '599ed16c138b5c86dfb8f6dfe5be49a628314a976009f2f2fd1dcbe1606ad5e7',
    '19c3bf8790277f5fe6d4003760a6c3ed9d391787be22814c3f8c1e21b5099ce8',
    '5c97ad08857292a8513f768c7af8681cc65093fa2bea7d2d823902b46fc2dfa6',
    '2ca465ef59cc7011e5ccbe6fc8c8c6310ee924fb1b7e8576ee95bf78d9e351a0',
  ],
  codex: [
    '48ea99367b909aae2a2f03d06be1fbe52846ecaaa4b3068e1f9b157923b23542',
    '53cce868a510607602b416b7404e2caffcd6c13b50f5c55c921e34a6aa7c8332',
    '6a45dbee15e24881993beb0ecd3c53836d6e4087837f39a865084fcd4b55d570',
    'f61e64516f49c02f560d541fdc6eef9ebd5f8610a4cc0757b4a20d21e56ddb5f',
  ],
});

function namedDeclaration(ast, type, name, subject) {
  return findBabel(ast, node => node.type === type && nameOf(node) === name, subject);
}

function textIncludes(source, node, fragments, subject) {
  const text = source.slice(node.start, node.end);
  for (const fragment of fragments) {
    if (!text.includes(fragment)) throw new Error(`${subject} no longer contains ${fragment}`);
  }
}

function sourceReference(entry) {
  return {
    authority_id: entry.id,
    repository: entry.repository,
    source_path: entry.source_path,
    snapshot_path: entry.snapshot_path,
    sha256: entry.sha256,
  };
}

function result(product, context, native, evidence, defeats) {
  const expected = REVIEWED_EVIDENCE[product.id];
  if (!expected || JSON.stringify(evidence.map(item => item.sha256)) !== JSON.stringify(expected)) {
    throw new Error(`${product.id} positive evidence differs from its semantic-review pins`);
  }
  return {
    product_id: product.id,
    governance_group: product.governance_group,
    declared_ecosystem: product.declared_ecosystem,
    native,
    evidence,
    source_references: context.entries(product.id).map(sourceReference),
    defeats,
  };
}

export function projectLobe(product, context) {
  const schema = context.ts('lobe.message_schema');
  const ui = context.ts('lobe.ui_message_types');
  const parse = context.ts('lobe.parse');
  const flat = context.ts('lobe.flat_list_builder');
  const messages = findBabel(schema.ast, node => node.type === 'VariableDeclarator' && nameOf(node) === 'messages', 'Lobe messages table');
  const uiMessage = namedDeclaration(ui.ast, 'TSInterfaceDeclaration', 'UIChatMessage', 'Lobe UIChatMessage');
  const parseFunction = findBabel(parse.ast, node => node.type === 'FunctionDeclaration' && nameOf(node) === 'parse', 'Lobe parse function');
  const flatten = findBabel(flat.ast, node => node.type === 'ClassMethod' && nameOf(node) === 'flatten', 'Lobe flatten method');
  textIncludes(schema.source, messages, ["role: varchar255('role').notNull()", "parentId: text('parent_id')", "agentId: text('agent_id')"], 'Lobe messages table');
  textIncludes(ui.source, uiMessage, ['id: string', 'role: UIMessageRoleType', 'children?: AssistantContentBlock[]', 'members?: UIChatMessage[]'], 'Lobe UI message');
  textIncludes(parse.source, parseFunction, ['flatList: recoveredFlatList', 'hiddenTaskCallbacks', 'messageMap: messageMapObj'], 'Lobe parse');
  textIncludes(flat.source, flatten, ['buildFlatListRecursive', 'flatList.sort', 'return flatList'], 'Lobe flatten');
  return result(product, context, {
    backing: 'parent_linked_messages_with_virtual_groups',
    selector: 'active_branch_resolution_plus_overlay_recovery',
    emitted: 'flatList',
    entry_identity: 'source_or_virtual_group',
  }, [
    utf16Evidence('lobe.message_schema', messages.type, messages.start, messages.end, schema.source),
    utf16Evidence('lobe.ui_message_types', uiMessage.type, uiMessage.start, uiMessage.end, ui.source),
    utf16Evidence('lobe.parse', parseFunction.type, parseFunction.start, parseFunction.end, parse.source),
    utf16Evidence('lobe.flat_list_builder', flatten.type, flatten.start, flatten.end, flat.source),
  ], [
    {kind: 'out_of_scope', affects: 'canonical_transcript', impact: 'disjoint', subject: 'lobe.complete_conversation', reason: 'paging, active branches, hidden internal dispatch, virtual grouping, and recovered overlays bound the projection'},
    {kind: 'authority_cannot_express', affects: 'universal_actor_enum', impact: 'disjoint', subject: 'portable_contributor', reason: 'roles, sender, agent, target, and grouped members do not select one universal contributor'},
  ]);
}

export function projectLibre(product, context) {
  const schema = context.ts('libre.message_schema');
  const tree = context.ts('libre.build_tree');
  const multi = context.ts('libre.multi_message', true);
  const messageSchema = findBabel(schema.ast, node => node.type === 'VariableDeclarator' && nameOf(node) === 'messageSchema', 'Libre message schema');
  const buildTree = findBabel(tree.ast, node => (node.type === 'FunctionDeclaration' || node.type === 'ArrowFunctionExpression') && tree.source.slice(node.start, node.start + 80).includes('buildTree'), 'Libre buildTree');
  const multiMessage = findBabel(multi.ast, node => (node.type === 'FunctionDeclaration' || node.type === 'ArrowFunctionExpression') && multi.source.slice(Math.max(0, node.start - 80), node.start + 120).includes('MultiMessage'), 'Libre MultiMessage');
  textIncludes(schema.source, messageSchema, ['messageId:', 'parentMessageId:', 'isCreatedByUser:', 'content:'], 'Libre schema');
  textIncludes(tree.source, buildTree, ['orderedMessages', 'parentMessage.children.push', 'rootMessages.push'], 'Libre buildTree');
  textIncludes(multi.source, multiMessage, ['siblingIdx', 'message.children', 'setSiblingIdx'], 'Libre MultiMessage');
  return result(product, context, {
    backing: 'two_pass_parent_tree',
    selector: 'per_parent_reverse_sibling_index_during_react_recursion',
    emitted: 'selected_recursive_message_route',
    entry_identity: 'stream_rewritable_message_id',
  }, [
    utf16Evidence('libre.message_schema', messageSchema.type, messageSchema.start, messageSchema.end, schema.source),
    utf16Evidence('libre.build_tree', buildTree.type, buildTree.start, buildTree.end, tree.source),
    utf16Evidence('libre.multi_message', multiMessage.type, multiMessage.start, multiMessage.end, multi.source),
  ], [
    {kind: 'out_of_scope', affects: 'canonical_transcript', impact: 'disjoint', subject: 'libre.sibling_branches', reason: 'the React route selects one sibling at each parent'},
    {kind: 'looked_and_blocked', affects: 'global_chronology', impact: 'disjoint', subject: 'libre.canonical_chronology', reason: 'native order and sibling selection do not establish a portable timestamp order'},
  ]);
}

export function projectOpenWeb(product, context) {
  const utility = context.ts('open_web.create_messages_list');
  const messagesSvelte = context.svelte('open_web.messages_view');
  const chats = context.python('open_web.chat_model');
  const messageModel = context.python('open_web.chat_message_model');
  const create = findBabel(utility.ast, node => node.type === 'VariableDeclarator' && nameOf(node) === 'createMessagesList', 'Open WebUI createMessagesList');
  textIncludes(utility.source, create, ['while (currentId !== null', 'list.push(message)', 'currentId = message.parentId', 'return list.reverse()'], 'Open WebUI createMessagesList');
  const chatClass = context.treeClass(chats, 'Chat');
  const messageClass = context.treeClass(messageModel, 'ChatMessage');
  for (const fragment of ['current_message_id', "id = Column(String", 'chat = Column(JSON)']) context.requireTreeText(chats, chatClass, fragment);
  for (const fragment of ['parent_id', 'role = Column', 'content = Column']) context.requireTreeText(messageModel, messageClass, fragment);
  const svelteText = messagesSvelte.source;
  if (!svelteText.includes('history.currentId') || !svelteText.includes('_messages.reverse()')) throw new Error('Open WebUI Messages view no longer consumes selected reverse path');
  return result(product, context, {
    backing: 'message_map_with_parent_and_children_plus_current_head',
    selector: 'walk_current_head_to_root_then_reverse',
    emitted: 'messages',
    entry_identity: 'message_id',
  }, [
    utf16Evidence('open_web.create_messages_list', create.type, create.start, create.end, utility.source),
    byteEvidence('open_web.chat_model', chatClass, chats.bytes),
    byteEvidence('open_web.chat_message_model', messageClass, messageModel.bytes),
    {source: 'open_web.messages_view', node_type: messagesSvelte.ast.type ?? 'Root', sha256: sha256(messagesSvelte.bytes), loc: {start: {line: 1, column: 0}, end: {line: svelteText.split('\n').length, column: 0}}, span: {utf16: {start: 0, end: svelteText.length}, utf8_bytes: {start: 0, end: messagesSvelte.bytes.length}}},
  ], [
    {kind: 'looked_and_blocked', affects: 'canonical_transcript', impact: 'disjoint', subject: 'open_web.missing_parent', reason: 'the native selector returns a partial suffix when a parent is absent'},
    {kind: 'authority_cannot_express', affects: 'universal_actor_enum', impact: 'disjoint', subject: 'open_web.role_as_participant', reason: 'subagent activity may retain user/assistant roles unrelated to participant identity'},
  ]);
}

export function projectChatUi(product, context) {
  const subtree = context.ts('chat_ui.build_subtree');
  const message = context.ts('chat_ui.message_type');
  const conversation = context.ts('chat_ui.conversation_type');
  const functionNode = findBabel(subtree.ast, node => node.type === 'FunctionDeclaration' && nameOf(node) === 'buildSubtree', 'Chat UI buildSubtree');
  const messageType = namedDeclaration(message.ast, 'TSTypeAliasDeclaration', 'Message', 'Chat UI Message');
  const conversationType = namedDeclaration(conversation.ast, 'TSInterfaceDeclaration', 'Conversation', 'Chat UI Conversation');
  textIncludes(subtree.source, functionNode, ['rootMessageId', 'message.ancestors', 'return ancestor', 'message,'], 'Chat UI buildSubtree');
  textIncludes(message.source, messageType, ['from: "user" | "assistant" | "system"', 'id:', 'ancestors?:', 'children?:'], 'Chat UI Message');
  textIncludes(conversation.source, conversationType, ['rootMessageId?', 'messages: Message[]'], 'Chat UI Conversation');
  return result(product, context, {
    backing: 'message_array_with_ancestor_and_child_links',
    selector: 'selected_leaf_ancestor_materialization',
    emitted: 'buildSubtree_return',
    entry_identity: 'message_id',
  }, [
    utf16Evidence('chat_ui.build_subtree', functionNode.type, functionNode.start, functionNode.end, subtree.source),
    utf16Evidence('chat_ui.message_type', messageType.type, messageType.start, messageType.end, message.source),
    utf16Evidence('chat_ui.conversation_type', conversationType.type, conversationType.start, conversationType.end, conversation.source),
  ], [
    {kind: 'looked_and_blocked', affects: 'canonical_transcript', impact: 'disjoint', subject: 'chat_ui.missing_ancestor', reason: 'the native selector throws when an ancestor is absent'},
    {kind: 'authority_cannot_express', affects: 'portable_payload', impact: 'disjoint', subject: 'chat_ui.visible_system_activity', reason: 'the pinned selector establishes returned records, not which native record kinds a later renderer presents'},
  ]);
}

export function projectGemini(product, context) {
  const types = context.ts('gemini.recording_types');
  const service = context.ts('gemini.recording_service');
  const base = namedDeclaration(types.ast, 'TSInterfaceDeclaration', 'BaseMessageRecord', 'Gemini BaseMessageRecord');
  const extras = namedDeclaration(types.ast, 'TSTypeAliasDeclaration', 'ConversationRecordExtra', 'Gemini ConversationRecordExtra');
  const conversation = namedDeclaration(types.ast, 'TSInterfaceDeclaration', 'ConversationRecord', 'Gemini ConversationRecord');
  const load = findBabel(service.ast, node => node.type === 'FunctionDeclaration' && nameOf(node) === 'loadConversationRecord', 'Gemini loadConversationRecord');
  textIncludes(types.source, base, ['id: string', 'content: PartListUnion'], 'Gemini BaseMessageRecord');
  textIncludes(types.source, extras, ["type: 'user' | 'info' | 'error' | 'warning'", "type: 'gemini'", 'toolCalls?: ToolCallRecord[]'], 'Gemini extras');
  textIncludes(types.source, conversation, ['sessionId: string', 'messages: MessageRecord[]'], 'Gemini ConversationRecord');
  textIncludes(service.source, load, ['isRewindRecord(record)', 'messagesMap.delete(id)', 'messagesMap.clear()', 'Array.from(messagesMap.values())', 'metadataOnly ? [] : loadedMessages'], 'Gemini loader');
  return result(product, context, {
    backing: 'append_record_with_rewind_and_checkpoint_materialization',
    selector: 'rewind_applied_before_map_insertion_order_projection',
    emitted: 'ConversationRecord.messages',
    entry_identity: 'message_record_id_with_nested_tool_records',
  }, [
    utf16Evidence('gemini.recording_types', base.type, base.start, base.end, types.source),
    utf16Evidence('gemini.recording_types', extras.type, extras.start, extras.end, types.source),
    utf16Evidence('gemini.recording_types', conversation.type, conversation.start, conversation.end, types.source),
    utf16Evidence('gemini.recording_service', load.type, load.start, load.end, service.source),
  ], [
    {kind: 'out_of_scope', affects: 'global_chronology', impact: 'disjoint', subject: 'gemini.rewound_suffix', reason: 'rewind records deliberately remove a previously materialized suffix'},
    {kind: 'out_of_scope', affects: 'portable_payload', impact: 'disjoint', subject: 'gemini.nested_tools_as_peer_activity', reason: 'tool records are nested inside Gemini message records'},
  ]);
}

export function projectCodex(product, context) {
  const thread = context.rust('codex.thread_data');
  const item = context.rust('codex.thread_item');
  const threadStruct = context.treeStruct(thread, 'Thread');
  const turnStruct = context.treeStruct(thread, 'Turn');
  const itemsView = context.treeEnum(thread, 'TurnItemsView');
  const itemEnum = context.treeEnum(item, 'ThreadItem');
  for (const fragment of ['pub id: String', 'pub session_id: String', 'pub forked_from_id: Option<String>', 'pub turns: Vec<Turn>']) context.requireTreeText(thread, threadStruct, fragment);
  for (const fragment of ['pub id: String', 'pub items: Vec<ThreadItem>', 'pub items_view: TurnItemsView']) context.requireTreeText(thread, turnStruct, fragment);
  for (const fragment of ['NotLoaded', 'Summary', 'Full']) context.requireTreeText(thread, itemsView, fragment);
  for (const fragment of ['UserMessage', 'AgentMessage', 'CollabAgentToolCall', 'SubAgentActivity']) context.requireTreeText(item, itemEnum, fragment);
  return result(product, context, {
    backing: 'thread_with_ordered_turns_and_native_thread_items',
    selector: 'thread_or_fork_local_returned_container_order',
    emitted: 'Turn.items',
    entry_identity: 'thread_item_id',
    native_extent: ['not_loaded', 'summary', 'full'],
  }, [
    byteEvidence('codex.thread_data', threadStruct, thread.bytes),
    byteEvidence('codex.thread_data', turnStruct, thread.bytes),
    byteEvidence('codex.thread_data', itemsView, thread.bytes),
    byteEvidence('codex.thread_item', itemEnum, item.bytes),
  ], [
    {kind: 'authority_cannot_express', affects: 'canonical_transcript', impact: 'disjoint', subject: 'codex.empty_items_means_no_activity', reason: 'TurnItemsView explicitly distinguishes not loaded, summary, and full'},
    {kind: 'out_of_scope', affects: 'global_chronology', impact: 'disjoint', subject: 'codex.global_branch_order', reason: 'fork lineage identifies separate thread-local paths'},
  ]);
}

function activityProjection(productId, scopeRefs, messageNamespace, ids, selector) {
  return {
    scope_refs: scopeRefs,
    extent: 'full',
    entries: ids.map(id => ({
      source_refs: [{namespace: messageNamespace, id}],
    })),
    native_selector: selector,
    verifier_fixture: 'selected_branch_to_ordered_projection/v1',
    source_product: productId,
  };
}

export function runBehavioralCases(context) {
  const open = context.ts('open_web.create_messages_list');
  const openNode = findBabel(open.ast, node => node.type === 'VariableDeclarator' && nameOf(node) === 'createMessagesList', 'Open WebUI behavior function');
  const openSource = `export const ${open.source.slice(openNode.start, openNode.end)};`;
  const createMessagesList = executeExportedTypescript(openSource, 'open-web-createMessagesList.ts', 'createMessagesList');

  const chat = context.ts('chat_ui.build_subtree');
  const chatNode = findBabel(chat.ast, node => node.type === 'FunctionDeclaration' && nameOf(node) === 'buildSubtree', 'Chat UI behavior function');
  const chatSource = `export ${chat.source.slice(chatNode.start, chatNode.end)}`;
  const buildSubtree = executeExportedTypescript(chatSource, 'chat-ui-buildSubtree.ts', 'buildSubtree');

  const openHistory = {
    messages: {
      s: {id: 's', parentId: null, childrenIds: ['u']},
      u: {id: 'u', parentId: 's', childrenIds: ['a', 'b']},
      a: {id: 'a', parentId: 'u', childrenIds: []},
      b: {id: 'b', parentId: 'u', childrenIds: []},
    },
    currentId: 'b',
  };
  const chatConversation = {
    rootMessageId: 's',
    messages: [
      {id: 's', ancestors: [], children: ['u']},
      {id: 'u', ancestors: ['s'], children: ['a', 'b']},
      {id: 'a', ancestors: ['s', 'u'], children: []},
      {id: 'b', ancestors: ['s', 'u'], children: []},
    ],
  };
  const selectedOpenInput = structuredClone(openHistory);
  const selectedChatInput = structuredClone(chatConversation);
  const ids = values => Array.from(values, value => value.id);
  const openSelected = ids(createMessagesList(openHistory, openHistory.currentId));
  const chatSelected = ids(buildSubtree(chatConversation, 'b'));
  if (JSON.stringify(openSelected) !== JSON.stringify(['s', 'u', 'b'])) throw new Error('Open WebUI selected-path behavior changed');
  if (JSON.stringify(chatSelected) !== JSON.stringify(['s', 'u', 'b'])) throw new Error('Chat UI selected-path behavior changed');

  openHistory.currentId = 'a';
  const openAlternate = ids(createMessagesList(openHistory, openHistory.currentId));
  const chatAlternate = ids(buildSubtree(chatConversation, 'a'));
  if (JSON.stringify(openAlternate) !== JSON.stringify(['s', 'u', 'a'])) throw new Error('Open WebUI alternate branch behavior changed');
  if (JSON.stringify(chatAlternate) !== JSON.stringify(['s', 'u', 'a'])) throw new Error('Chat UI alternate branch behavior changed');

  const brokenOpen = {messages: {b: {id: 'b', parentId: 'missing', childrenIds: []}}, currentId: 'b'};
  const openBroken = ids(createMessagesList(brokenOpen, 'b'));
  let chatFailure = null;
  try {
    buildSubtree({rootMessageId: 's', messages: [{id: 'b', ancestors: ['missing']}]}, 'b');
  } catch (error) {
    chatFailure = error.message;
  }
  if (JSON.stringify(openBroken) !== JSON.stringify(['b']) || chatFailure !== 'Ancestor not found') throw new Error('missing-parent falsifier behavior changed');

  return {
    protocol: 'org.gooi.fixture.activity_projection_behavior/v1',
    case: 'selected_branch_to_ordered_projection',
    fixture: {
      graph: 'system -> user -> {assistant_a, assistant_b}',
      selected: 'assistant_b',
      native_inputs: {
        open_webui: selectedOpenInput,
        chat_ui: selectedChatInput,
      },
    },
    observations: [
      {
        product_id: 'open_webui',
        ordered_source_ids: openSelected,
        activity_projection: activityProjection(
          'open_webui',
          [
            {namespace: 'open_webui.history_root', id: openSelected[0]},
            {namespace: 'open_webui.history_head', id: 'b'},
          ],
          'open_webui.message',
          openSelected,
          'createMessagesList(history, history.currentId)',
        ),
        source_node: utf16Evidence('open_web.create_messages_list', openNode.type, openNode.start, openNode.end, open.source),
      },
      {
        product_id: 'chat_ui',
        ordered_source_ids: chatSelected,
        activity_projection: activityProjection(
          'chat_ui',
          [
            {namespace: 'chat_ui.root_message', id: chatConversation.rootMessageId},
            {namespace: 'chat_ui.selected_message', id: 'b'},
          ],
          'chat_ui.message',
          chatSelected,
          "buildSubtree(conversation, 'b')",
        ),
        source_node: utf16Evidence('chat_ui.build_subtree', chatNode.type, chatNode.start, chatNode.end, chat.source),
      },
    ],
    alternate_selection: {selected: 'assistant_a', open_webui: openAlternate, chat_ui: chatAlternate},
    malformed_topology: {
      open_webui: {result: openBroken, classification: 'partial_projection'},
      chat_ui: {error: chatFailure, classification: 'blocking_unknown'},
      admitted: false,
    },
    claim_limit: 'executes reviewed exact upstream function nodes in an isolated context and verifies concrete ActivityProjection values; does not execute either application dependency closure or establish rendered visual equivalence',
  };
}
