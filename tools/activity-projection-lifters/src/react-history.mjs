import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export const REVIEWED_USE_HISTORY_SHA256 = '01b769034ac7fb9ff1cb934ff6a1863b29efe02517657aa3ba70da3b0fa4dc3c';

const TOOL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WORKER_PATH = fileURLToPath(new URL('./react-history-worker.mjs', import.meta.url));
const DEFAULT_TIMEOUT_MS = 5_000;

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function executeUseHistoryTrace(functionSource, fixture, options = {}) {
  if (typeof functionSource !== 'string' || sha256(functionSource) !== REVIEWED_USE_HISTORY_SHA256) {
    throw new Error('Gemini useHistory source is not the exact review-pinned function node');
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) throw new Error('React history timeout must be a positive integer');

  const request = JSON.stringify({functionSource, fixture});
  if (request === undefined) throw new Error('React history fixture is not a JSON value');
  const child = spawnSync(
    process.execPath,
    [
      '--experimental-permission',
      `--allow-fs-read=${TOOL_ROOT}`,
      WORKER_PATH,
    ],
    {
      encoding: 'utf8',
      env: {NODE_ENV: 'test'},
      input: request,
      maxBuffer: 1024 * 1024,
      timeout: timeoutMs,
    },
  );
  if (child.error?.code === 'ETIMEDOUT') throw new Error(`reviewed React history execution timed out after ${timeoutMs}ms`);
  if (child.error) throw new Error(`reviewed React history worker failed: ${child.error.message}`, {cause: child.error});
  if (child.status !== 0) {
    const detail = child.stderr.trim() || `exit status ${child.status}`;
    throw new Error(`reviewed React history worker rejected execution: ${detail}`);
  }
  try {
    return JSON.parse(child.stdout);
  } catch (error) {
    throw new Error('reviewed React history worker returned invalid JSON', {cause: error});
  }
}
