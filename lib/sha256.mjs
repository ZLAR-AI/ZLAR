import { createHash } from 'node:crypto';

export function sha256hex(data) {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}
