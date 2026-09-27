// Single-valued installed Demo 1 profile.
// These constants are source identity, not runtime configuration. The root
// installer must refuse any local identity or path that differs.

export const INSTALLED_PROFILE_ID = 'zlar.demo1.c-backed.v1';
export const INSTALLED_CLAIM_CEILING = 'installed_c_backed_candidate_evidence_only';
export const CLIENT_USER = 'vincentnijjar';
export const CLIENT_UID = 501;
export const CLIENT_PRINCIPAL_ID = 'macos-euid:501';
export const SERVICE_USER = '_zlar_demo1';
export const SERVICE_GROUP = '_zlar_demo1';
export const SERVICE_UID = 450;
export const SERVICE_GID = 450;
export const ADMIN_GROUP = 'admin';
export const ADMIN_GID = 80;
export const AUTHORITY_TRANSFER_UID = 501;
export const AUTHORITY_TRANSFER_GID = 20;
export const AUTHORITY_TRANSFER_MODE = 0o700;
export const SOCKET_GROUP_GID = 80;

export const C_ROOT_KEY_ID = 'spki-sha256:eb746072b61c1f21225e6504accf55ec99d5ba73f3117c80e0d092c1436ab07c';
export const C_ROOT_PUBLIC_PEM_SHA256 = '4260a266c255059b041b8af5805b89fdaa5dfb5c40a291a146842deda2b09890';
export const EXPECTED_NODE_SHA256 = '245e0321af97d3c21dd4e7104457334dfe3c3ba7982d0db75363e354565f8cbb';
export const EXPECTED_CLANG_SHA256 = 'b8763cf250e607a778bb4603cecb5b90338814d0a3dfcba0d57b1de242f610e9';
export const EXPECTED_BROKER_SHA256 = 'a5a2ee64e734563470ea35ec9c7686b9fc77b895cbe4f417735ffc1e2a057878';

export const INSTALLED_PATHS = Object.freeze({
  broker: '/usr/local/libexec/zlar-demo1-destination',
  runtimeRoot: '/usr/local/libexec/zlar-demo1',
  node: '/usr/local/libexec/zlar-demo1/node',
  service: '/usr/local/libexec/zlar-demo1/demos/zlar-destination-gate/demo1-installed-service.mjs',
  clientModule: '/usr/local/libexec/zlar-demo1/demos/zlar-destination-gate/demo1.mjs',
  protocol: '/usr/local/libexec/zlar-demo1/cyan/demo1-protocol.mjs',
  store: '/usr/local/libexec/zlar-demo1/cyan/demo1-store.mjs',
  destination: '/usr/local/libexec/zlar-demo1/cyan/demo1-destination.mjs',
  handler: '/usr/local/libexec/zlar-demo1/demos/zlar-destination-gate/demo1-installed-handler.mjs',
  profile: '/usr/local/libexec/zlar-demo1/demos/zlar-destination-gate/demo1-installed-profile.mjs',
  client: '/usr/local/bin/zlar-demo1',
  authorize: '/usr/local/bin/zlar-demo1-authorize',
  policy: '/etc/zlar/demo1-authority-roots.json',
  cRootPublicKey: '/etc/zlar/demo1-founder-authority-root-c-v1.pub.pem',
  issuerPrivateKey: '/etc/zlar/demo1-issuer-key.pem',
  issuerPublicKey: '/etc/zlar/demo1-issuer-public.pem',
  destinationPrivateKey: '/etc/zlar/demo1-destination-key.pem',
  destinationPublicKey: '/etc/zlar/demo1-destination-public.pem',
  installationManifest: '/etc/zlar/demo1-installation-manifest.json',
  stateRoot: '/var/db/zlar-demo1',
  database: '/var/db/zlar-demo1/state.sqlite',
  stagingRoot: '/var/tmp/zlar-demo1-staging',
  stagedObject: '/var/tmp/zlar-demo1-staging/demo-1-release.json',
  authorityTransferRoot: '/var/tmp/zlar-demo1-authority',
  challenge: '/var/tmp/zlar-demo1-authority/challenge-n.json',
  signedGrant: '/var/tmp/zlar-demo1-authority/grant-g.json',
  socket: '/var/run/zlar-demo1.sock',
  launchdPlist: '/Library/LaunchDaemons/ai.zlar.demo1-destination.plist',
});

export const LAUNCHD_LABEL = 'ai.zlar.demo1-destination';
export const LAUNCHD_SOCKET_NAME = 'Demo1DestinationSocket';
export const IPC_MAX_BYTES = 1024 * 1024;
export const CHALLENGE_LIFETIME_SECONDS = 300;
