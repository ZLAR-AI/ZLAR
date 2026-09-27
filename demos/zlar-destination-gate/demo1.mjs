#!/usr/local/libexec/zlar-demo1/node
// Sole outward Demo 1 client. It only stages harmless bytes and transports
// canonical requests over the protected destination socket. It cannot load
// keys, policy, state, or an in-process destination.

import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  lstatSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import net from 'node:net';
import { basename, dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  bodyId,
  canonicalBytes,
  parseCanonical,
} from '../../cyan/demo1-protocol.mjs';
import {
  CLIENT_UID,
  INSTALLED_PATHS,
  IPC_MAX_BYTES,
} from './demo1-installed-profile.mjs';

class ClientRefusal extends Error {
  constructor(code) {
    super(code);
    this.name = 'ClientRefusal';
    this.code = code;
  }
}

function refuse(condition, code) {
  if (!condition) throw new ClientRefusal(code);
}

function loadJson(path) {
  refuse(typeof path === 'string', 'file_argument_missing');
  const node = lstatSync(path);
  refuse(node.isFile() && !node.isSymbolicLink() && node.nlink === 1, 'input_file_refused');
  return parseCanonical(readFileSync(path));
}

function unwrap(value, field) {
  return value?.[field] ?? value;
}

function requestId() {
  return `req-${randomBytes(18).toString('base64url')}`;
}

export function buildClientRequest(argv) {
  const [operation, ...args] = argv;
  switch (operation) {
    case 'health':
    case 'challenge':
    case 'evidence':
      refuse(args.length === 0, 'usage');
      return { operation };
    case 'credential': {
      refuse(args.length === 1, 'usage');
      return { operation, grant: unwrap(loadJson(args[0]), 'grant') };
    }
    case 'refuse': {
      refuse(args.length === 1 || args.length === 2, 'usage');
      const challenge = unwrap(loadJson(args[0]), 'challenge');
      return {
        operation: 'promote',
        request: {
          request_id: args[1] ?? requestId(),
          challenge_id: bodyId('challenge', challenge.body),
          grant: null,
          credential: null,
        },
      };
    }
    case 'promote': {
      refuse(args.length === 3 || args.length === 4, 'usage');
      const challenge = unwrap(loadJson(args[0]), 'challenge');
      const grant = unwrap(loadJson(args[1]), 'grant');
      const credential = unwrap(loadJson(args[2]), 'credential');
      return {
        operation,
        request: {
          request_id: args[3] ?? requestId(),
          challenge_id: bodyId('challenge', challenge.body),
          grant,
          credential,
        },
      };
    }
    default:
      throw new ClientRefusal('usage');
  }
}

export function stageFile(inputPath) {
  refuse(process.geteuid?.() === CLIENT_UID, 'client_uid_refused');
  const input = readFileSync(inputPath);
  refuse(input.length > 0 && input.length <= IPC_MAX_BYTES, 'staged_bytes_length');
  const temporary = join(dirname(INSTALLED_PATHS.stagedObject), `.demo-1-release.${process.pid}.${randomBytes(8).toString('hex')}`);
  refuse(basename(INSTALLED_PATHS.stagedObject) === 'demo-1-release.json', 'staged_path_refused');
  writeFileSync(temporary, input, { flag: 'wx', mode: 0o640 });
  chmodSync(temporary, 0o640);
  renameSync(temporary, INSTALLED_PATHS.stagedObject);
  return { v: 1, status: 'STAGED', byte_length: input.length };
}

export function sendRequest(request) {
  const body = canonicalBytes(request);
  refuse(body.length > 0 && body.length <= IPC_MAX_BYTES, 'request_length');
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: INSTALLED_PATHS.socket });
    const chunks = [];
    let expected = null;
    let received = 0;
    socket.setTimeout(15000);
    socket.on('connect', () => {
      const header = Buffer.alloc(4);
      header.writeUInt32BE(body.length);
      socket.write(Buffer.concat([header, body]));
    });
    socket.on('data', (chunk) => {
      try {
        chunks.push(chunk);
        received += chunk.length;
        if (expected === null && received >= 4) {
          const combined = Buffer.concat(chunks);
          expected = combined.readUInt32BE(0);
          refuse(expected > 0 && expected <= IPC_MAX_BYTES, 'response_length');
        }
        if (expected !== null && received === expected + 4) socket.end();
        if (expected !== null && received > expected + 4) socket.destroy(new ClientRefusal('response_overrun'));
      } catch (error) {
        socket.destroy(error);
      }
    });
    socket.on('timeout', () => socket.destroy(new ClientRefusal('destination_timeout')));
    socket.on('error', reject);
    socket.on('close', () => {
      try {
        const raw = Buffer.concat(chunks);
        refuse(expected !== null && raw.length === expected + 4, 'response_truncated');
        resolve(parseCanonical(raw.subarray(4)));
      } catch (error) {
        reject(error);
      }
    });
  });
}

export async function clientMain(argv) {
  try {
    refuse(process.geteuid?.() === CLIENT_UID, 'client_uid_refused');
    let outputPath = null;
    const outputIndex = argv.indexOf('--output');
    if (outputIndex !== -1) {
      refuse(outputIndex === argv.length - 2 && argv.indexOf('--output', outputIndex + 1) === -1, 'usage');
      outputPath = argv.at(-1);
      argv = argv.slice(0, -2);
    }
    const result = argv[0] === 'stage'
      ? (refuse(argv.length === 2 && outputPath === null, 'usage'), stageFile(argv[1]))
      : await sendRequest(buildClientRequest(argv));
    if (outputPath === null) {
      process.stdout.write(`${canonicalBytes(result).toString('utf8')}\n`);
    } else {
      if (argv[0] === 'challenge') refuse(outputPath === INSTALLED_PATHS.challenge, 'challenge_output_path_refused');
      writeFileSync(outputPath, canonicalBytes(result), { flag: 'wx', mode: 0o640 });
      chmodSync(outputPath, 0o640);
      process.stdout.write(`${JSON.stringify({ status: result.status, output: outputPath })}\n`);
    }
    return result?.status === 'REFUSED' || result?.status === 'EFFECT_REFUSED' ? 42 : 0;
  } catch (error) {
    const notInstalled = error?.code === 'ENOENT' || error?.code === 'ECONNREFUSED';
    process.stderr.write(`${JSON.stringify({
      v: 1,
      status: notInstalled ? 'REFUSED_NOT_INSTALLED' : 'REFUSED',
      destination_reached: false,
      reason: error?.code ?? error?.message ?? 'client_failure',
      effect_delta: 0,
    })}\n`);
    return 42;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exitCode = await clientMain(process.argv.slice(2));
}
