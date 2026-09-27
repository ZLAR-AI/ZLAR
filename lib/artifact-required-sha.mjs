const SHA256_HEX_RE = /^[a-f0-9]{64}$/;

export function assertRequiredSha256(value, optionName = '--require-sha') {
  if (!SHA256_HEX_RE.test(value || '')) {
    throw new Error(`${optionName} must be a 64-character lowercase SHA-256 hex digest.`);
  }
}
export function bindRequiredBodySha256(verification, requiredSha256, label = 'Artifact') {
  if (!requiredSha256) {
    return verification;
  }
  assertRequiredSha256(requiredSha256);
  if (!verification || verification.body_sha256 !== requiredSha256) {
    throw new Error(`${label} SHA-256 does not match required --require-sha value.`);
  }
  return {
    ...verification,
    required_body_sha256: requiredSha256,
    required_body_sha256_matched: true,
  };
}

export function formatRequiredBodySha256Posture(verification) {
  if (!verification?.required_body_sha256) {
    return '';
  }
  return [
    `required_body_sha256=${verification.required_body_sha256}`,
    'required_body_sha256_matched=true',
  ].join('\n') + '\n';
}
