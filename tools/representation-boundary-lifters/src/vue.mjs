import { NodeTypes, ElementTypes, parse as parseTemplate } from '@vue/compiler-dom';
import { parse as parseSfc } from '@vue/compiler-sfc';

import { sortBySpan, sourceEvidence } from './evidence.mjs';

function withBase(authorityId, nodeType, loc, baseOffset, source) {
  return sourceEvidence(
    authorityId,
    nodeType,
    baseOffset + loc.start.offset,
    baseOffset + loc.end.offset,
    source,
  );
}

function sfcEvidence(authorityId, nodeType, loc, source) {
  return sourceEvidence(authorityId, nodeType, loc.start.offset, loc.end.offset, source);
}

function templateTagType(tagType) {
  if (tagType === ElementTypes.ELEMENT) return 'element';
  if (tagType === ElementTypes.COMPONENT) return 'component';
  if (tagType === ElementTypes.SLOT) return 'slot';
  if (tagType === ElementTypes.TEMPLATE) return 'template';
  return 'unknown';
}

function walkTemplate(root, visitor) {
  const seen = new WeakSet();
  const visit = (value) => {
    if (!value || typeof value !== 'object' || seen.has(value)) return;
    seen.add(value);
    if (typeof value.type === 'number') visitor(value);
    for (const [key, child] of Object.entries(value)) {
      if (key === 'loc' || key === 'codegenNode') continue;
      if (Array.isArray(child)) child.forEach(visit);
      else visit(child);
    }
  };
  visit(root);
}

function blockRecord(authorityId, blockKind, index, block, source) {
  return {
    block_kind: blockKind,
    index,
    lang: block.lang ?? null,
    scoped: block.scoped ?? false,
    module: block.module ?? false,
    src: block.src ?? null,
    evidence: sfcEvidence(authorityId, 'SfcBlock', block.loc, source),
  };
}

export function inventoryVueSfc(authority, source) {
  let descriptor;
  try {
    const result = parseSfc(source, {
      filename: authority.source_path,
      sourceMap: false,
    });
    if (result.errors.length > 0) {
      const details = result.errors.map((error) => error.message ?? String(error)).join('; ');
      throw new Error(details);
    }
    descriptor = result.descriptor;
  } catch (error) {
    throw new Error(`Vue SFC parser rejected ${authority.id}: ${error.message}`, { cause: error });
  }

  const blocks = [];
  if (descriptor.template) blocks.push(blockRecord(authority.id, 'template', 0, descriptor.template, source));
  if (descriptor.script) blocks.push(blockRecord(authority.id, 'script', 0, descriptor.script, source));
  if (descriptor.scriptSetup) {
    blocks.push(blockRecord(authority.id, 'script_setup', 0, descriptor.scriptSetup, source));
  }
  descriptor.styles.forEach((block, index) => {
    blocks.push(blockRecord(authority.id, 'style', index, block, source));
  });
  descriptor.customBlocks.forEach((block, index) => {
    blocks.push(blockRecord(authority.id, 'custom', index, block, source));
  });

  const templateRoots = [];
  const tags = [];
  const directives = [];
  const interpolations = [];
  const dynamicComponents = [];
  const routerViews = [];
  const teleports = [];

  if (descriptor.template) {
    let root;
    try {
      root = parseTemplate(descriptor.template.content, {
        comments: true,
      });
    } catch (error) {
      throw new Error(`Vue template parser rejected ${authority.id}: ${error.message}`, {
        cause: error,
      });
    }
    const baseOffset = descriptor.template.loc.start.offset;
    templateRoots.push({
      child_count: root.children.length,
      evidence: withBase(authority.id, 'Root', root.loc, baseOffset, source),
    });

    walkTemplate(root, (node) => {
      if (node.type === NodeTypes.ELEMENT) {
        const type = templateTagType(node.tagType);
        const item = {
          name: node.tag,
          tag_type: type,
          evidence: withBase(authority.id, 'Element', node.loc, baseOffset, source),
        };
        tags.push(item);

        const normalized = node.tag.toLowerCase();
        if (normalized === 'component') dynamicComponents.push({ ...item });
        if (normalized === 'router-view' || normalized === 'routerview') routerViews.push({ ...item });
        if (normalized === 'teleport') teleports.push({ ...item });

        for (const prop of node.props) {
          if (prop.type === NodeTypes.DIRECTIVE) {
            directives.push({
              name: prop.name,
              argument:
                prop.arg?.type === NodeTypes.SIMPLE_EXPRESSION && prop.arg.isStatic
                  ? prop.arg.content
                  : null,
              modifiers: prop.modifiers.map((modifier) => modifier.content),
              evidence: withBase(authority.id, 'Directive', prop.loc, baseOffset, source),
            });
          }
        }
      } else if (node.type === NodeTypes.INTERPOLATION) {
        interpolations.push({
          evidence: withBase(authority.id, 'Interpolation', node.loc, baseOffset, source),
        });
      }
    });
  }

  const collections = {
    blocks: sortBySpan(blocks),
    template_roots: sortBySpan(templateRoots),
    tags: sortBySpan(tags),
    directives: sortBySpan(directives),
    interpolations: sortBySpan(interpolations),
    dynamic_components: sortBySpan(dynamicComponents),
    router_views: sortBySpan(routerViews),
    teleports: sortBySpan(teleports),
  };

  return {
    kind: 'vue_sfc',
    parsed: true,
    parser_configuration: {
      sfc: { source_map: false },
      template: { comments: true },
    },
    counts: Object.fromEntries(
      Object.entries(collections).map(([name, items]) => [name, items.length]),
    ),
    ...collections,
  };
}

export const vueParserConfiguration = Object.freeze({
  sfc: { source_map: false },
  template: { comments: true },
});
