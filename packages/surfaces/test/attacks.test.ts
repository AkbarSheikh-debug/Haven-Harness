import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { sanitizeForDisplay } from '@hn/core';
import {
  McpConnection,
  applyImport,
  createCopy,
  createSafeFiles,
  dockerIsUp,
  findBash,
  findDocker,
  findHelper,
  planImport,
  type SafeFiles,
} from '@hn/operations';
import { Gate, Jail, isSecretPath, parsePolicy, type ApprovalCard } from '@hn/security';
import { ContainerSandbox, loadMcpConfig, parseApproval, quotaProblem } from '@hn/surfaces';
import { withTempDir } from '@hn/testkit';

const packages = fileURLToPath(new URL('../../', import.meta.url));
const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));

/** Attacks that the plan names, tagged with the phase whose feature they target. A phase may not close with its own names missing. */
const BUILT_IN_PHASE_2 = [
  'hostile_image_cannot_fake_canary', 'external_sandbox_refused_on_workstation', 'nested_gitdir_and_bare_repo_rejected_on_import', 'linked_worktree_gitfile_rewrite_rejected',
  'git_dir_rename_cannot_replace_config', 'host_exec_manifest_blocks_import', 'ci_workflow_write_requires_human', 'checkpoint_excludes_secrets', 'global_git_filter_not_invoked',
  'submodule_fsmonitor_not_executed_after_session', 'rollback_refuses_while_box_alive', 'rollback_reports_skipped_paths', 'git_history_secret_not_readable_in_box',
  'control_file_hash_change_reprompts', 'harness_exec_requires_gate_below_tier3', 'spawn_never_uses_cwd_binary_windows', 'proto_pollution_config_cannot_widen',
  'agents_md_symlink_to_secret_not_loaded', 'symlink_swap_during_read_write', 'hardlink_to_denied_file_refused', 'dotenv_case_variants_masked', 'osc52_and_osc8_stripped_all_doors',
  'terminal_reply_cannot_answer_approval', 'approval_invalid_after_script_edit', 'bidi_and_overwrite_approval_escaped', 'parent_session_grant_not_inherited', 'guardian_cannot_approve_external',
  'ssrf_metadata_and_loopback_blocked', 'dns_subdomain_exfil_blocked_pre_resolve', 'redirect_revalidated', 'unmarked_repo_counts_private', 'path_encoded_exfil_blocked_under_taint',
  'mcp_sampling_denied', 'stdio_mcp_env_allowlist', 'web_to_file_to_read_stays_tainted', 'scan_redos_times_out_denied', 'forged_log_grants_nothing', 'zstd_bomb_rejected',
  'call_tool_unwrapped_before_gate', 'recursive_hn_cannot_reset_taint', 'yolo_without_sandbox', 'disk_quota_blocks_bind_mount_fill',
] as const;

/** Phase 3 attacks whose feature is built. The rest of Phase 3's names stay below until their task lands. */
const BUILT_IN_PHASE_3 = ['deep_agents_md_cannot_evict_user_rules', 'exit_plan_mode_requires_human', 'option_click_not_user_origin', 'box_job_cannot_use_tool_socket', 'read_image_decompression_bomb_contained'] as const;

/** Phase 4 attacks whose feature is built. The rest of Phase 4's names stay below until their task lands. */
const BUILT_IN_PHASE_4 = ['daily_note_web_line_not_autoloaded', 'recall_gates_ignore_injected_queries', 'card_shows_exact_stored_bytes'] as const;

/** Phase 5a attacks whose feature is built. */
const BUILT_IN_PHASE_5A = ['external_provider_refused_in_yolo', 'handoff_keeps_taint'] as const;

/** Phase 5b attacks whose feature is built. */
const BUILT_IN_PHASE_5B = ['member_cannot_move_main_ref', 'vm_escape_refused_below_tier3'] as const;

/** Phase 6 attacks whose feature is built. */
const BUILT_IN_PHASE_6 = ['steer_ipc_rejected_without_token', 'tainted_schedule_requires_human'] as const;

/** Phase 7 attacks whose feature is built. The rest stay below until their task lands. */
const BUILT_IN_PHASE_7 = ['plugin_backend_cannot_claim_tier', 'image_recipe_edit_requires_human_on_resume', 'devcontainer_initialize_command_never_runs', 'dockerfile_context_excludes_secrets', 'prepare_cannot_publish_or_reach_engine_api', 'markdown_image_never_fetched', 'serve_rejects_foreign_origin_and_rebinding'] as const;

/** Phase 8 attacks: the exit gate's modified client against the broker. */
const BUILT_IN_PHASE_8 = ['modified_client_cannot_reach_denied_model', 'modified_client_never_receives_broker_key', 'denied_tool_call_stripped_from_reply', 'modified_client_cannot_call_denied_server_tool', 'modified_client_cannot_push_protected_ref_without_approval', 'requester_cannot_approve_own_request', 'stolen_token_refused_for_other_session_and_after_revoke', 'forged_id_token_refused', 'old_policy_bundle_cannot_be_replayed', 'budget_cannot_be_reset_by_client', 'memory_from_other_ou_never_returned', 'cut_audit_tail_caught_by_anchor', 'external_sandbox_untested_is_refused'] as const;

/** Phase 10 attacks: the claim that hn runs inside a benchmark container that is its only boundary. */
const BUILT_IN_PHASE_10 = ['benchmark_container_refused_on_workstation', 'benchmark_container_needs_operator_allow_entry', 'benchmark_container_never_yolo'] as const;

/** Phase 12 attacks: the editor extension against a hostile agent or folder, and the GitHub Action against a hostile issue. */
const BUILT_IN_PHASE_12 = [
  'editor_diff_shows_exact_bytes_written', 'editor_diff_reveals_hidden_characters', 'editor_agent_cannot_read_files_or_start_terminals', 'editor_agent_cannot_pick_allow_always',
  'editor_oversized_line_and_garbage_contained', 'editor_reject_is_never_turned_into_allow', 'editor_text_flood_contained', 'editor_untrusted_folder_starts_nothing',
  'editor_folder_settings_cannot_choose_binary_or_model_server', 'editor_installed_extension_not_run_in_untrusted_folder',
  'issue_text_cannot_close_the_untrusted_frame', 'issue_text_cannot_become_a_command', 'issue_text_is_untrusted_event_not_instruction', 'issue_label_from_non_writer_runs_nothing',
  'issue_planted_workflow_never_reaches_pull_request', 'github_token_never_reaches_hn', 'patch_with_symlink_submodule_binary_or_protected_path_refused', 'patch_to_protected_path_pushes_nothing',
  'agent_job_holds_no_write_token', 'workflow_never_pastes_issue_text_into_a_command', 'report_text_cannot_link_or_mention', 'forged_log_report_refused',
] as const;

/** Names for features that belong to a later phase, so they cannot have a test yet. The phase is the one that must add it. */
const LATER_PHASES: Readonly<Record<string, string>> = {
};

async function testFiles(): Promise<{ name: string; text: string }[]> {
  const found: { name: string; text: string }[] = [];
  for (const pkg of await readdir(packages)) {
    for (const file of await readdir(join(packages, pkg, 'test')).catch(() => [] as string[])) {
      if (file.endsWith('.test.ts')) found.push({ name: `${pkg}/${file}`, text: await readFile(join(packages, pkg, 'test', file), 'utf8') });
    }
  }
  return found;
}

describe('the attack suite for Phase 2', () => {
  it('has a test titled with every attack the plan names for a feature this phase built', async () => {
    const files = await testFiles();
    const missing = BUILT_IN_PHASE_2.filter((name) => !files.some((file) => new RegExp(`(?:it|describe)\\(\\s*['"\`][^'"\`\\n]*${name}`).test(file.text)));
    assert.deepEqual(missing, [], 'a Phase 2 attack has no test, so the phase cannot close');
  });

  it('lists every other named attack with the later phase that must add it, and none of those is a phase-2 feature', () => {
    for (const [name, phase] of Object.entries(LATER_PHASES)) {
      assert.match(phase, /^[3-8][ab]?$/, name);
      assert.ok(!(BUILT_IN_PHASE_2 as readonly string[]).includes(name), `${name} is listed as both built and later`);
      assert.ok(!(BUILT_IN_PHASE_3 as readonly string[]).includes(name), `${name} is listed as both built and later`);
      assert.ok(!(BUILT_IN_PHASE_4 as readonly string[]).includes(name), `${name} is listed as both built and later`);
      assert.ok(!(BUILT_IN_PHASE_5A as readonly string[]).includes(name), `${name} is listed as both built and later`);
      assert.ok(!(BUILT_IN_PHASE_5B as readonly string[]).includes(name), `${name} is listed as both built and later`);
      assert.ok(!(BUILT_IN_PHASE_6 as readonly string[]).includes(name), `${name} is listed as both built and later`);
      assert.ok(!(BUILT_IN_PHASE_7 as readonly string[]).includes(name), `${name} is listed as both built and later`);
      assert.ok(!(BUILT_IN_PHASE_8 as readonly string[]).includes(name), `${name} is listed as both built and later`);
      assert.ok(!(BUILT_IN_PHASE_10 as readonly string[]).includes(name), `${name} is listed as both built and later`);
      assert.ok(!(BUILT_IN_PHASE_12 as readonly string[]).includes(name), `${name} is listed as both built and later`);
    }
    const all = [...BUILT_IN_PHASE_2, ...BUILT_IN_PHASE_3, ...BUILT_IN_PHASE_4, ...BUILT_IN_PHASE_5A, ...BUILT_IN_PHASE_5B, ...BUILT_IN_PHASE_6, ...BUILT_IN_PHASE_7, ...BUILT_IN_PHASE_8, ...BUILT_IN_PHASE_10, ...BUILT_IN_PHASE_12, ...Object.keys(LATER_PHASES)];
    assert.equal(new Set(all).size, all.length, 'a name is listed twice');
  });

  it('has a test titled with every Phase 3 attack whose feature is built', async () => {
    const files = await testFiles();
    const missing = BUILT_IN_PHASE_3.filter((name) => !files.some((file) => new RegExp(`(?:it|describe)\\(\\s*['"\`][^'"\`\\n]*${name}`).test(file.text)));
    assert.deepEqual(missing, [], 'a built Phase 3 attack has no test');
  });

  it('has a test titled with every Phase 5a attack whose feature is built', async () => {
    const files = await testFiles();
    const missing = BUILT_IN_PHASE_5A.filter((name) => !files.some((file) => new RegExp(`(?:it|describe)\\(\\s*['"\`][^'"\`\\n]*${name}`).test(file.text)));
    assert.deepEqual(missing, [], 'a built Phase 5a attack has no test');
  });

  it('has a test titled with every Phase 5b attack whose feature is built', async () => {
    const files = await testFiles();
    const missing = BUILT_IN_PHASE_5B.filter((name) => !files.some((file) => new RegExp(`(?:it|describe)\\(\\s*['"\`][^'"\`\\n]*${name}`).test(file.text)));
    assert.deepEqual(missing, [], 'a built Phase 5b attack has no test');
  });

  it('has a test titled with every Phase 6 attack whose feature is built', async () => {
    const files = await testFiles();
    const missing = BUILT_IN_PHASE_6.filter((name) => !files.some((file) => new RegExp(`(?:it|describe)\\(\\s*['"\`][^'"\`\\n]*${name}`).test(file.text)));
    assert.deepEqual(missing, [], 'a built Phase 6 attack has no test');
  });

  it('has a test titled with every Phase 7 attack whose feature is built', async () => {
    const files = await testFiles();
    const missing = BUILT_IN_PHASE_7.filter((name) => !files.some((file) => new RegExp(`(?:it|describe)\\(\\s*['"\`][^'"\`\\n]*${name}`).test(file.text)));
    assert.deepEqual(missing, [], 'a built Phase 7 attack has no test');
  });

  it('has a test titled with every Phase 8 attack whose feature is built', async () => {
    const files = await testFiles();
    const missing = BUILT_IN_PHASE_8.filter((name) => !files.some((file) => new RegExp(`(?:it|describe)\\(\\s*['"\`][^'"\`\\n]*${name}`).test(file.text)));
    assert.deepEqual(missing, [], 'a built Phase 8 attack has no test');
  });

  it('has a test titled with every Phase 10 attack whose feature is built', async () => {
    const files = await testFiles();
    const missing = BUILT_IN_PHASE_10.filter((name) => !files.some((file) => new RegExp(`(?:it|describe)\\(\\s*['"\`][^'"\`\\n]*${name}`).test(file.text)));
    assert.deepEqual(missing, [], 'a built Phase 10 attack has no test');
  });

  it('has a test titled with every Phase 12 attack whose feature is built', async () => {
    const files = await testFiles();
    const missing = BUILT_IN_PHASE_12.filter((name) => !files.some((file) => new RegExp(`(?:it|describe)\\(\\s*['"\`][^'"\`\\n]*${name}`).test(file.text)));
    assert.deepEqual(missing, [], 'a built Phase 12 attack has no test');
  });

  it('has a test titled with every Phase 4 attack whose feature is built', async () => {
    const files = await testFiles();
    const missing = BUILT_IN_PHASE_4.filter((name) => !files.some((file) => new RegExp(`(?:it|describe)\\(\\s*['"\`][^'"\`\\n]*${name}`).test(file.text)));
    assert.deepEqual(missing, [], 'a built Phase 4 attack has no test');
  });
});

describe('attacks that are not tested anywhere else', () => {
  let files: SafeFiles;
  before(async () => {
    const helper = await findHelper({ env: {}, repoRoot });
    assert.ok(helper !== null, 'hn-sandbox is not built. Run: pnpm build:sandbox');
    files = createSafeFiles(helper);
  });

  it('attack: git_dir_rename_cannot_replace_config (a folder the box renames to .git is held for a person)', async () => {
    await withTempDir(async (dir) => {
      const base = await realpath(dir);
      const host = join(base, 'host');
      const copy = join(base, 'copy');
      await mkdir(join(host, '.git'), { recursive: true });
      await writeFile(join(host, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n');
      await writeFile(join(host, 'a.txt'), 'a');
      const { baseline } = await createCopy(host, copy);
      // In the box: build a folder with a hostile config, then rename it to .git.
      await mkdir(join(copy, 'evil'));
      await writeFile(join(copy, 'evil', 'config'), '[core]\n\tfsmonitor = touch pwned');
      await rename(join(copy, 'evil'), join(copy, '.git'));
      const plan = await planImport(host, copy, baseline);
      assert.deepEqual(plan.auto, []);
      assert.deepEqual(plan.gated.map((change) => change.path), ['.git/config']);
      const result = await applyImport(plan, { files, hostRoot: host, copyRoot: copy, baseline });
      assert.deepEqual(result.applied, []);
      assert.equal(await readFile(join(host, '.git', 'config'), 'utf8'), '[core]\n\trepositoryformatversion = 0\n', 'the host git config was replaced');
    });
  });

  it('attack: submodule_fsmonitor_not_executed_after_session (nothing runs git, so a hostile config cannot fire)', async () => {
    await withTempDir(async (dir) => {
      const base = await realpath(dir);
      const host = join(base, 'host');
      const copy = join(base, 'copy');
      const canary = join(base, 'canary.txt');
      await mkdir(host);
      await writeFile(join(host, 'a.txt'), 'a');
      const { baseline } = await createCopy(host, copy);
      const hostile = `[core]\n\tfsmonitor = node -e "require('fs').writeFileSync('${canary.replaceAll('\\', '/')}','x')"\n`;
      await mkdir(join(copy, 'sub', '.git'), { recursive: true });
      await writeFile(join(copy, 'sub', '.git', 'config'), hostile);
      await writeFile(join(copy, '.gitmodules'), '[submodule "x"]\n\tpath = sub\n\turl = https://example.invalid/x\n');
      const plan = await planImport(host, copy, baseline);
      // Even when a person approves every one of them, importing is only copying bytes: no program is started.
      const approved = new Map(plan.gated.map((change) => [change.path, change.hash ?? 'delete'] as const));
      await applyImport(plan, { files, hostRoot: host, copyRoot: copy, baseline, approved });
      await new Promise((resolve) => setTimeout(resolve, 500));
      assert.equal(await stat(canary).then(() => true, () => false), false, 'something ran the hostile config');
    });
  });

  it('attack: global_git_filter_not_invoked (no code in the harness starts git, so no filter or hook can be named)', async () => {
    const offenders: string[] = [];
    for (const pkg of await readdir(packages)) {
      for (const folder of ['src', 'bin']) {
        for (const file of await readdir(join(packages, pkg, folder), { recursive: true }).catch(() => [] as string[])) {
          if (!/\.(ts|mjs)$/.test(file)) continue;
          const text = await readFile(join(packages, pkg, folder, file), 'utf8');
          if (/(spawn|spawnSync|execFile|execFileSync|exec|execSync)\(\s*['"`][^'"`]*\bgit(\.exe)?['"`]/.test(text) || /\[\s*['"`]git['"`]\s*,\s*\[/.test(text)) offenders.push(`${pkg}/${folder}/${file}`);
        }
      }
    }
    assert.deepEqual(offenders, [], 'the harness starts git, which reads .git/config and .gitattributes from a tree a box wrote');
  });

  it('attack: spawn_never_uses_cwd_binary_windows (programs are found by absolute path, never by a name the project could shadow)', async () => {
    const planted = await mkdtemp(join(tmpdir(), 'hn-planted-'));
    const before = process.cwd();
    try {
      for (const name of ['bash.exe', 'docker.exe', 'rg.exe', 'node.exe', 'git.exe', 'bash', 'docker']) await writeFile(join(planted, name), 'planted');
      process.chdir(planted);
      const bash = findBash();
      assert.ok(isAbsolute(bash), bash);
      assert.ok(!bash.toLowerCase().startsWith(planted.toLowerCase()), 'a planted bash was chosen');
      const docker = await findDocker({ ...process.env, HN_DOCKER_BIN: '' });
      assert.ok(docker === null || (isAbsolute(docker) && !docker.toLowerCase().startsWith(planted.toLowerCase())), `a planted docker was chosen: ${docker}`);
      await assert.rejects(McpConnection.start({ command: 'node', args: ['-e', '0'] }), /absolute path/);
      await assert.rejects(McpConnection.start({ command: './bash.exe' }), /absolute path/);
      const { ContainerBox } = await import('@hn/operations');
      await assert.rejects(ContainerBox.start({ image: `alpine@sha256:${'a'.repeat(64)}`, sessionId: 'x', workDir: planted, docker: 'docker' }), /absolute path/);
    } finally {
      process.chdir(before);
      await rm(planted, { recursive: true, force: true });
    }
  });

  it('attack: proto_pollution_config_cannot_widen (a __proto__ or constructor key in a config is refused, and nothing is polluted)', async () => {
    const hostile = [
      '{"version":1,"__proto__":{"tools":{"allow":["*"]}}}',
      '{"version":1,"tools":{"__proto__":{"allow":["*"]},"deny":["bash"]}}',
      '{"version":1,"constructor":{"prototype":{"maxMode":"yolo"}}}',
      '{"version":1,"tools":{"constructor":{"prototype":{"polluted":true}}}}',
    ];
    for (const text of hostile) assert.throws(() => parsePolicy(JSON.parse(text)), /unknown field/, text);
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'mcp.json'), '{"servers":[{"name":"a","command":"/x","version":"1","__proto__":{"effects":{"all":"observe"}}}]}');
      await assert.rejects(loadMcpConfig(dir), /unknown field "__proto__"/);
    });
    assert.equal(({} as Record<string, unknown>)['allow'], undefined);
    assert.equal(({} as Record<string, unknown>)['maxMode'], undefined);
    assert.equal(({} as Record<string, unknown>)['polluted'], undefined);
  });

  it('attack: dotenv_case_variants_masked (every spelling of a secret file is stopped, for reads, writes and the shell)', async () => {
    const variants = ['.env', '.ENV', '.Env.Local', '.env.production', '.env.', '.env ', '.env..', 'sub/.ENV', 'sub\\.env', '.env::$DATA', '.ENV::$DATA', './.env', 'a/../.env'];
    const gate = new Gate({ mode: 'yolo', tier: 4, workdir: '/repo', jail: new Jail({ root: '/repo', platform: 'linux', realpath: async (path) => path }), audit: () => undefined });
    for (const path of variants) {
      assert.equal(isSecretPath(path), true, path);
      for (const write of [false, true]) {
        const decision = await gate.check({ id: 'c', tool: write ? 'write_file' : 'read_file', args: {}, effect: write ? 'reversible' : 'observe', paths: [{ path, write }], summary: 's' });
        assert.equal(decision.kind, 'rejected', `${write ? 'write' : 'read'} ${path}`);
      }
    }
    for (const ok of ['.env.example', '.env.sample', 'environment.md', 'src/env.ts']) assert.equal(isSecretPath(ok), false, ok);
    const windows = new Jail({ root: 'D:\\repo', platform: 'win32', realpath: async (path) => path });
    for (const short of ['ENV~1', 'sub\\ENV~1.TXT']) await assert.rejects(windows.resolve(short), /8\.3 short names/);
  });

  it('attack: terminal_reply_cannot_answer_approval (a terminal query in model text never reaches the terminal, and only a plain yes approves)', () => {
    const queries = ['\u001b[6n', '\u001b[5n', '\u001b[c', '\u001b[>0c', '\u001b]11;?\u0007', '\u001bP$qm\u001b\\', '\u001b[?1;2c', '\u001b[18t', '\u001b[21t', '\u001bZ', '\u009b6n'];
    for (const query of queries) {
      const shown = sanitizeForDisplay(`before ${query} after`);
      assert.ok(!/[\u001b\u009b\u009d\u0007]/.test(shown), `a terminal query got through: ${JSON.stringify(query)}`);
    }
    const card: ApprovalCard = { approvalId: 'a', tool: 'bash', effect: 'execution', summary: 'ls', byteCount: 2, canRememberForSession: false };
    for (const reply of ['\u001b[1;1R', '1;1R', 'y\u001b[0n', '\u001b[0n', 'yes please', 'y;y', '\u001b[?1;2cy', 'sure', '1', 'Y\u0000', 'yy']) {
      assert.equal(parseApproval(reply, card), 'deny', JSON.stringify(reply));
    }
    for (const reply of ['y', 'Y', 'yes', ' YES ']) assert.equal(parseApproval(reply, card), 'once', reply);
  });
});

describe('the disk quota decision, without a container', () => {
  it('attack: disk_quota_blocks_bind_mount_fill (the measurement that stops a box)', async () => {
    await withTempDir(async (dir) => {
      const copy = await realpath(dir);
      assert.equal(await quotaProblem(copy, 1_000, 100), null, 'an empty copy is within any limit');
      await writeFile(join(copy, 'small.bin'), Buffer.alloc(900));
      assert.equal(await quotaProblem(copy, 1_000, 100), null);
      await mkdir(join(copy, 'deep', 'er'), { recursive: true });
      await writeFile(join(copy, 'deep', 'er', 'big.bin'), Buffer.alloc(500));
      assert.match((await quotaProblem(copy, 1_000, 100)) ?? '', /wrote more than 1000 bytes/);
    });
  });

  it('counts files and folders too, so millions of tiny files cannot fill the disk', async () => {
    await withTempDir(async (dir) => {
      const copy = await realpath(dir);
      for (let i = 0; i < 30; i += 1) await writeFile(join(copy, `f${i}`), '');
      assert.match((await quotaProblem(copy, 1_000_000, 20)) ?? '', /created more than 20 files/);
      assert.equal(await quotaProblem(copy, 1_000_000, 100), null);
    });
  });

  it('does not follow a link out of the copy, so it cannot be tricked into counting (or hiding) the host', async () => {
    await withTempDir(async (dir) => {
      const base = await realpath(dir);
      const copy = join(base, 'copy');
      const outside = join(base, 'outside');
      await mkdir(copy);
      await mkdir(outside);
      await writeFile(join(outside, 'huge.bin'), Buffer.alloc(50_000));
      const { symlinkSync } = await import('node:fs');
      symlinkSync(outside, join(copy, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
      assert.equal(await quotaProblem(copy, 1_000, 100), null, 'a link in the copy made a host file count against it');
    });
  });
});

describe('the disk quota', async () => {
  const docker = await findDocker();
  const up = docker !== null && (await dockerIsUp(docker));
  const options = { skip: up ? false : 'Docker is not running' };
  let sandbox: ContainerSandbox | undefined;
  let root = '';

  after(async () => {
    await sandbox?.stop();
    if (root !== '') await rm(root, { recursive: true, force: true });
  });

  it('attack: disk_quota_blocks_bind_mount_fill (a box that writes past its limit is stopped, and says why)', options, async () => {
    const helper = await findHelper({ env: {}, repoRoot });
    assert.ok(helper !== null);
    root = await realpath(await mkdtemp(join(tmpdir(), 'hn-quota-')));
    const host = join(root, 'host');
    await mkdir(host);
    await writeFile(join(host, 'a.txt'), 'a');
    const image = (() => {
      const run = (...args: string[]): string => execFileSync(docker as string, args, { encoding: 'utf8' }).trim();
      try {
        return run('image', 'inspect', 'alpine:3.20', '--format', '{{index .RepoDigests 0}}').replace(/^docker\.io\/library\//, '');
      } catch {
        run('pull', '-q', 'alpine:3.20');
        return run('image', 'inspect', 'alpine:3.20', '--format', '{{index .RepoDigests 0}}').replace(/^docker\.io\/library\//, '');
      }
    })();
    sandbox = await ContainerSandbox.open({ kind: 'container', image, diskLimitBytes: 3_000_000, diskCheckMs: 300 }, { home: join(root, 'home'), sessionId: `quota${process.pid}`, hostRoot: host, files: createSafeFiles(helper) });
    assert.equal(sandbox.alive, true);
    await sandbox.bash.exec('dd if=/dev/zero of=/work/fill.bin bs=1048576 count=12 2>/dev/null; echo done', { cwd: '/work', timeoutMs: 30_000, signal: new AbortController().signal });
    for (let waited = 0; sandbox.alive && waited < 15_000; waited += 250) await new Promise((resolve) => setTimeout(resolve, 250));
    assert.equal(sandbox.alive, false, 'the box kept running after it passed its limit');
    assert.match(sandbox.quotaExceeded ?? '', /wrote more than 3000000 bytes/);
    assert.throws(() => sandbox?.bash.exec('echo hi', { cwd: '/work', timeoutMs: 5_000, signal: new AbortController().signal }), (error: Error & { code?: string }) => error.code === 'BOX_QUOTA' && /was stopped/.test(error.message));
  });
});
