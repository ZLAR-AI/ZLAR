#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AGENT_PASSENGER_LAB_REPORT_TYPE,
  assertAgentPassengerLabReport,
  assertNoUnsafeAgentPassengerLabText,
} from '../lib/agent-passenger-lab.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

function assert(label, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function runZlar(args) {
  return spawnSync(join(process.cwd(), 'bin', 'zlar'), args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

console.log('\n-- agent passenger lab cli --');

const textRun = runZlar(['agent-passenger-lab']);
assertEqual('text exits zero', 0, textRun.status);
assertEqual('text stderr empty', '', textRun.stderr);
assert('text output privacy safe', assertNoUnsafeAgentPassengerLabText(textRun.stdout));
assert('text names command', textRun.stdout.includes('ZLAR Agent Passenger Lab v1'));
assert('text names pipeline', textRun.stdout.includes('proposal -> action_class -> route'));
assert('text names live probing false', textRun.stdout.includes('live_probing=false'));
assert('text names authority invariant', textRun.stdout.includes('agent_outputs_are_traffic_not_authority=true'));
assert('text names observation non-authority', textRun.stdout.includes('observation_may_create_authority=false'));
assert('text names non-claims', textRun.stdout.includes('Non-claims:'));

const jsonRun = runZlar(['agent-passenger-lab', '--json']);
assertEqual('json exits zero', 0, jsonRun.status);
assertEqual('json stderr empty', '', jsonRun.stderr);
assert('json output privacy safe', assertNoUnsafeAgentPassengerLabText(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report validates', assertAgentPassengerLabReport(report));
assertEqual('json report type', AGENT_PASSENGER_LAB_REPORT_TYPE, report.report_type);
assertEqual('json result', 'PASS', report.result);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json role count', 10, report.counts.passenger_role_count);
assertEqual('json scenario count', 6, report.counts.scenario_count);
assertEqual('json authority laundering seen', true, report.coverage_learning.authority_laundering_seen);
assertEqual('json creates authority false', false, report.claim_boundary.creates_authority);
assertEqual('json production governance false', false, report.claim_boundary.production_governance);

const tempRoot = mkdtempSync(join(tmpdir(), 'zlar-agent-passenger-lab-'));
try {
  const reportPath = join(tempRoot, 'zlar-agent-passenger-lab-v1.json');
  const jsonOutRun = runZlar(['agent-passenger-lab', '--json-out', reportPath]);
  assertEqual('json-out exits zero', 0, jsonOutRun.status);
  assertEqual('json-out stdout empty', '', jsonOutRun.stdout);
  assertEqual('json-out stderr empty', '', jsonOutRun.stderr);
  const writtenReport = JSON.parse(readFileSync(reportPath, 'utf8'));
  assert('json-out report validates', assertAgentPassengerLabReport(writtenReport));
  assertEqual('json-out report type', AGENT_PASSENGER_LAB_REPORT_TYPE, writtenReport.report_type);

  const overwriteRun = runZlar(['agent-passenger-lab', '--json-out', reportPath]);
  assertEqual('overwrite exits one', 1, overwriteRun.status);
  assertEqual('overwrite stdout empty', '', overwriteRun.stdout);
  assert('overwrite stderr safe', assertNoUnsafeAgentPassengerLabText(overwriteRun.stderr));
  assert('overwrite refuses existing path', overwriteRun.stderr.includes('Refusing to overwrite existing output path'));

  const conflictRun = runZlar(['agent-passenger-lab', '--json', '--json-out', join(tempRoot, 'conflict.json')]);
  assertEqual('json/json-out conflict exits two', 2, conflictRun.status);
  assertEqual('json/json-out conflict stdout empty', '', conflictRun.stdout);
  assert('json/json-out conflict stderr safe', assertNoUnsafeAgentPassengerLabText(conflictRun.stderr));
  assert('json/json-out conflict reported', conflictRun.stderr.includes('Cannot combine --json with --json-out.'));
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}

const helpRun = runZlar(['agent-passenger-lab', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assertEqual('help stdout empty', '', helpRun.stdout);
assert('help stderr safe', assertNoUnsafeAgentPassengerLabText(helpRun.stderr));
assert('help names usage', helpRun.stderr.includes('Usage: zlar agent-passenger-lab [--json|--json-out <file>]'));
assert('help states fixture boundary', helpRun.stderr.includes('local fixture'));
assert('help states no live agents', helpRun.stderr.includes('does not spawn live agents'));
assert('help states no authority', helpRun.stderr.includes('create authority'));

const unsupportedRun = runZlar(['agent-passenger-lab', '--bogus']);
assertEqual('unsupported exits two', 2, unsupportedRun.status);
assertEqual('unsupported stdout empty', '', unsupportedRun.stdout);
assert('unsupported stderr safe', assertNoUnsafeAgentPassengerLabText(unsupportedRun.stderr));
assert('unsupported option reported', unsupportedRun.stderr.includes('Unsupported option provided.'));

const missingOutputRun = runZlar(['agent-passenger-lab', '--json-out']);
assertEqual('missing json-out value exits two', 2, missingOutputRun.status);
assertEqual('missing json-out value stdout empty', '', missingOutputRun.stdout);
assert('missing json-out value stderr safe', assertNoUnsafeAgentPassengerLabText(missingOutputRun.stderr));
assert('missing json-out value reported', missingOutputRun.stderr.includes('Missing value for --json-out.'));

const mainHelpRun = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelpRun.status);
assertEqual('main help stderr empty', '', mainHelpRun.stderr);
assert('main help lists command', mainHelpRun.stdout.includes('agent-passenger-lab'));

console.log(`\nAgent passenger lab CLI tests: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  process.exit(1);
}
