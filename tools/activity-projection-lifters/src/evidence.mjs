import {createHash} from 'node:crypto';

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function positionAt(source, offset) {
  const lines = source.slice(0, offset).split('\n');
  return {line: lines.length, column: lines.at(-1).length};
}

export function utf16Evidence(authorityId, nodeType, start, end, source) {
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start || end > source.length) {
    throw new Error(`invalid UTF-16 span ${start}..${end} for ${authorityId}`);
  }
  const selected = Buffer.from(source.slice(start, end), 'utf8');
  return {
    source: authorityId,
    node_type: nodeType,
    sha256: sha256(selected),
    loc: {start: positionAt(source, start), end: positionAt(source, end)},
    span: {
      utf16: {start, end},
      utf8_bytes: {
        start: Buffer.byteLength(source.slice(0, start), 'utf8'),
        end: Buffer.byteLength(source.slice(0, end), 'utf8'),
      },
    },
  };
}

export function byteEvidence(authorityId, node, sourceBytes) {
  const start = node.startIndex;
  const end = node.endIndex;
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start || end > sourceBytes.length) {
    throw new Error(`invalid byte span ${start}..${end} for ${authorityId}`);
  }
  const prefix = sourceBytes.subarray(0, start).toString('utf8');
  const body = sourceBytes.subarray(start, end).toString('utf8');
  return {
    source: authorityId,
    node_type: node.type,
    sha256: sha256(sourceBytes.subarray(start, end)),
    loc: {
      start: {line: node.startPosition.row + 1, column: node.startPosition.column},
      end: {line: node.endPosition.row + 1, column: node.endPosition.column},
    },
    span: {
      utf16: {start: prefix.length, end: prefix.length + body.length},
      utf8_bytes: {start, end},
    },
  };
}

export function excerpt(source, evidence) {
  return source.slice(evidence.span.utf16.start, evidence.span.utf16.end);
}
