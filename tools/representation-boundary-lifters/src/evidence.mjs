import { createHash } from 'node:crypto';

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function positionAt(source, offset) {
  const prefix = source.slice(0, offset);
  const lines = prefix.split('\n');
  return {
    line: lines.length,
    column: lines.at(-1).length,
  };
}

export function sourceEvidence(authorityId, nodeType, start, end, source) {
  if (
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    start < 0 ||
    end < start ||
    end > source.length
  ) {
    throw new Error(`invalid source span ${start}..${end} for ${authorityId}`);
  }

  return {
    source: authorityId,
    node_type: nodeType,
    loc: {
      start: positionAt(source, start),
      end: positionAt(source, end),
    },
    span: {
      utf16: { start, end },
      utf8: {
        start: Buffer.byteLength(source.slice(0, start), 'utf8'),
        end: Buffer.byteLength(source.slice(0, end), 'utf8'),
      },
    },
  };
}

export function sortBySpan(items) {
  return items.sort((left, right) => {
    const offset = left.evidence.span.utf16.start - right.evidence.span.utf16.start;
    if (offset !== 0) return offset;
    return left.evidence.span.utf16.end - right.evidence.span.utf16.end;
  });
}
