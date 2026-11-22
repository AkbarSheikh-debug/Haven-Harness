/**
 * The attack registry: every named attack hn claims to resist, in one place.
 *
 * Three things are made from this list and checked against it, so none of them can drift:
 *   - the test suite (`packages/surfaces/test/attacks.test.ts`): every name here has a test titled with it, and a test titled
 *     `attack: <name>` for a name that is not here fails;
 *   - the public page `docs/guide/attacks.md`, written by `scripts/attack-catalog.ts` (the page also links each test);
 *   - a test that fails when the committed page is not exactly what the script writes.
 *
 * A description says what the attacker does and what must NOT happen, in words for someone who has not seen the code.
 * This file imports nothing, so a script can load it without building anything.
 */

export interface Attack {
  readonly name: string;
  readonly area: string;
  readonly description: string;
}

/** The areas, in the order the public page shows them. */
export const AREAS = [
  'The permission gate and approvals',
  'Untrusted input',
  'Files and secrets',
  'Git and imports',
  'Sandboxes and boxes',
  'Network and the web',
  'Tools, MCP and other programs',
  'Session log, memory and instructions',
  'Agents, teams and schedules',
  'The terminal and the local web page',
  'Team broker',
  'Editor extension',
  'GitHub Action',
  'Signing keys, rotation and revocation',
] as const;

export type Area = (typeof AREAS)[number];

const attack = (area: Area, name: string, description: string): Attack => ({ name, area, description });
const GATE: Area = 'The permission gate and approvals';
const UNTRUSTED: Area = 'Untrusted input';
const FILES: Area = 'Files and secrets';
const GIT: Area = 'Git and imports';
const BOX: Area = 'Sandboxes and boxes';
const NET: Area = 'Network and the web';
const TOOLS: Area = 'Tools, MCP and other programs';
const LOG: Area = 'Session log, memory and instructions';
const AGENTS: Area = 'Agents, teams and schedules';
const SURFACE: Area = 'The terminal and the local web page';
const BROKER: Area = 'Team broker';
const EDITOR: Area = 'Editor extension';
const ACTION: Area = 'GitHub Action';
const KEYS: Area = 'Signing keys, rotation and revocation';

export const ATTACKS: readonly Attack[] = [
  // The permission gate and approvals.
  attack(GATE, 'yolo_without_sandbox', 'Asking for the mode that skips approvals on a machine with no verified box is refused, and the refusal says why.'),
  attack(GATE, 'ci_workflow_write_requires_human', 'A write to a file the host would later run (a CI workflow) always asks a person, even in the mode that normally lets edits through.'),
  attack(GATE, 'approval_invalid_after_script_edit', 'A script a person approved to run stops being approved the moment its contents change.'),
  attack(GATE, 'bidi_and_overwrite_approval_escaped', 'Text that reverses direction or overwrites earlier characters cannot make an approval card show something other than what will run.'),
  attack(GATE, 'guardian_cannot_approve_external', 'The automatic reviewer can never approve an action that reaches outside the machine; only a person can.'),
  attack(GATE, 'exit_plan_mode_requires_human', 'The model cannot leave plan mode by itself; a person has to agree.'),
  attack(GATE, 'option_click_not_user_origin', 'An option the model offers and a person clicks is not treated as the person having typed that instruction.'),
  attack(GATE, 'harness_exec_requires_gate_below_tier3', 'Running the project\'s own verify command asks a person first, even in the mode that lets edits through, unless a verified box holds it.'),
  attack(GATE, 'call_tool_unwrapped_before_gate', 'A tool found through the deferred-tool search still goes through the permission gate before it runs.'),
  attack(GATE, 'terminal_reply_cannot_answer_approval', 'A terminal query hidden in model text never reaches the terminal, and only a plain "yes" typed by the person approves.'),
  attack(GATE, 'parent_session_grant_not_inherited', 'A permission granted to one session, or a stolen token, is useless for another session or audience.'),
  attack(GATE, 'external_provider_refused_in_yolo', 'An outside agent program is refused in the no-approvals mode, before any card is shown, and the program never starts.'),

  // Untrusted input.
  attack(UNTRUSTED, 'web_to_file_to_read_stays_tainted', 'Text fetched from the web, saved to a file and read back later is still treated as untrusted.'),
  attack(UNTRUSTED, 'unmarked_repo_counts_private', 'A repository nobody marked public counts as private, and a single mark does not clear that.'),
  attack(UNTRUSTED, 'recursive_hn_cannot_reset_taint', 'A second hn started from inside a session may only look; it cannot launder untrusted input into trusted work.'),
  attack(UNTRUSTED, 'handoff_keeps_taint', 'A session continued from another starts as untrusted as its parent, is linked to it, and the hand-off note is never taken for the user.'),
  attack(UNTRUSTED, 'daily_note_web_line_not_autoloaded', 'A line of web text saved in a memory note is not loaded into the next session as if it were trusted.'),

  // Files and secrets.
  attack(FILES, 'agents_md_symlink_to_secret_not_loaded', 'An instruction file that is really a link to a secret (a hard link on Windows) is not loaded.'),
  attack(FILES, 'symlink_swap_during_read_write', 'Swapping a path for a link between the check and the read or write does not get the tool outside the project.'),
  attack(FILES, 'hardlink_to_denied_file_refused', 'A hard link inside the project to a file that is off limits is refused.'),
  attack(FILES, 'dotenv_case_variants_masked', 'Every spelling of a secrets file (upper case, mixed case) is stopped for reads, writes and the shell.'),
  attack(FILES, 'proto_pollution_config_cannot_widen', 'A __proto__ or constructor key in a config file is refused and nothing is polluted, so a config cannot widen permissions.'),
  attack(FILES, 'checkpoint_excludes_secrets', 'A checkpoint of the project never contains a secret, by name, by content or in nested places.'),
  attack(FILES, 'read_image_decompression_bomb_contained', 'A tiny image file claiming to be 50,000 by 50,000 pixels is refused unopened and nothing from it goes to the model.'),
  attack(FILES, 'spawn_never_uses_cwd_binary_windows', 'Programs are found by absolute path, never by a name the project could shadow with its own file.'),
  attack(FILES, 'rollback_refuses_while_box_alive', 'Rolling files back is refused while the box that could be writing to them is still running.'),
  attack(FILES, 'rollback_reports_skipped_paths', 'A rollback says what it could not restore, and what was never saved, instead of claiming everything came back.'),

  // Git and imports.
  attack(GIT, 'nested_gitdir_and_bare_repo_rejected_on_import', 'A nested git directory or bare repository inside what a box hands back is rejected.'),
  attack(GIT, 'linked_worktree_gitfile_rewrite_rejected', 'A file named .git that points somewhere else is rejected when a box\'s work comes back.'),
  attack(GIT, 'git_dir_rename_cannot_replace_config', 'A folder the box renames to .git is held for a person instead of replacing the project\'s git settings.'),
  attack(GIT, 'host_exec_manifest_blocks_import', 'Anything that would run code on the host when it comes back from a box waits for a human.'),
  attack(GIT, 'git_history_secret_not_readable_in_box', 'Ordinary files come back from the box, what runs code on the host is held, and the box is never shown a secret from git history.'),
  attack(GIT, 'global_git_filter_not_invoked', 'No code in hn starts git on its own, so a filter or hook named in a user\'s global git settings cannot run.'),
  attack(GIT, 'submodule_fsmonitor_not_executed_after_session', 'A hostile submodule setting that names a program to run cannot fire, because nothing runs git after the session.'),

  // Sandboxes and boxes.
  attack(BOX, 'hostile_image_cannot_fake_canary', 'A container image with fake network tools cannot pass the verifier, which checks from outside the box.'),
  attack(BOX, 'external_sandbox_refused_on_workstation', 'A claim that hn is already inside someone else\'s sandbox is refused on a machine that looks like a workstation.'),
  attack(BOX, 'external_sandbox_untested_is_refused', 'A claimed sandbox with no probe tools proves nothing, so the claim is refused.'),
  attack(BOX, 'benchmark_container_refused_on_workstation', 'The benchmark-container claim is refused on a workstation even with the allow entry and the variable both in place.'),
  attack(BOX, 'benchmark_container_needs_operator_allow_entry', 'The benchmark-container claim is refused without an allow entry in the person\'s own home folder.'),
  attack(BOX, 'benchmark_container_never_yolo', 'A claimed outer container is capped at the ask-nothing mode with an explicit allow list; every other mode, and no list, is refused.'),
  attack(BOX, 'plugin_backend_cannot_claim_tier', 'A plugin that says it provides a high-isolation tier but runs on this machine is counted as the machine\'s own tier.'),
  attack(BOX, 'box_job_cannot_use_tool_socket', 'A background job in a box never receives the harness socket, a tool token or a model key.'),
  attack(BOX, 'disk_quota_blocks_bind_mount_fill', 'A box that tries to fill the disk through a mounted folder is stopped by the quota.'),
  attack(BOX, 'image_recipe_edit_requires_human_on_resume', 'A box image recipe edited after approval is not used until a person approves the change, a resume included.'),
  attack(BOX, 'devcontainer_initialize_command_never_runs', 'A dev container\'s lifecycle commands, run arguments, mounts and privileges are listed as ignored and never run.'),
  attack(BOX, 'dockerfile_context_excludes_secrets', 'An image build sees only the named files, never a secret, a .git folder, a link or a hard link.'),
  attack(BOX, 'prepare_cannot_publish_or_reach_engine_api', 'The image-preparing step cannot publish, log in, reach the container engine\'s API, reach another host or traverse paths.'),

  // Network and the web.
  attack(NET, 'ssrf_metadata_and_loopback_blocked', 'Cloud metadata addresses and the machine\'s own loopback are refused, however the address is written.'),
  attack(NET, 'dns_subdomain_exfil_blocked_pre_resolve', 'Data hidden in a subdomain name is refused before the resolver is ever asked.'),
  attack(NET, 'redirect_revalidated', 'A redirect to an internal address is refused before anything connects to it.'),
  attack(NET, 'path_encoded_exfil_blocked_under_taint', 'While the session holds untrusted input, only the exact web address the user typed may be fetched, so data cannot leave in a path.'),

  // Tools, MCP and other programs.
  attack(TOOLS, 'mcp_sampling_denied', 'A tool server cannot ask the model for completions, ask the user questions or list roots; only a ping is answered.'),
  attack(TOOLS, 'stdio_mcp_env_allowlist', 'A tool server started by hn inherits no environment, no home folder and no project.'),
  attack(TOOLS, 'scan_redos_times_out_denied', 'A pattern built to make the safety scan run forever is cut off and the call is denied.'),

  // Session log, memory and instructions.
  attack(LOG, 'forged_log_grants_nothing', 'A session log forged without the key grants nothing: no approvals, no trust, no resume.'),
  attack(LOG, 'zstd_bomb_rejected', 'A log frame that expands far beyond the size it declared is stopped at the declared size.'),
  attack(LOG, 'recall_gates_ignore_injected_queries', 'Text planted in a memory cannot change which memories the recall step lets through.'),
  attack(LOG, 'card_shows_exact_stored_bytes', 'The card a person approves for a memory write shows exactly the bytes that will be stored.'),
  attack(LOG, 'control_file_hash_change_reprompts', 'An approved instruction file that changes shows the difference and waits for a person again.'),
  attack(LOG, 'deep_agents_md_cannot_evict_user_rules', 'A deeply nested instruction file cannot push the user\'s own rules out of the model\'s context.'),
  attack(LOG, 'forged_log_replay_refused', 'A session log with one byte changed, a frame removed, moved or added, or the wrong key is refused by the replay screen, and nothing of what it held is shown.'),
  attack(LOG, 'forged_log_report_refused', 'A report made from an edited session log is refused and says nothing about what the log contains.'),

  // Agents, teams and schedules.
  attack(AGENTS, 'member_cannot_move_main_ref', 'A team member that tries to move main or run update-ref reaches nothing; only the merge queue moves the branch.'),
  attack(AGENTS, 'vm_escape_refused_below_tier3', 'A workflow script\'s escape payload never runs, because the tool refuses before any script runner starts.'),
  attack(AGENTS, 'tainted_schedule_requires_human', 'A scheduled task built from untrusted text is refused when unattended and shown in full to a person when attended.'),
  attack(AGENTS, 'steer_ipc_rejected_without_token', 'A message sent to a running session with no token, a wrong one or junk adds nothing; the right one adds a row that is never the user\'s.'),

  // The terminal and the local web page.
  attack(SURFACE, 'osc52_and_osc8_stripped_all_doors', 'Terminal escape codes that write the clipboard or hide a link are stripped from model text at every door.'),
  attack(SURFACE, 'markdown_image_never_fetched', 'In the local web page a model\'s image becomes text, raw HTML is escaped, and nothing is fetched to show it.'),
  attack(SURFACE, 'serve_rejects_foreign_origin_and_rebinding', 'The local web page answers only on loopback and checks Host, Origin, cookie and CSRF token on every request.'),
  attack(SURFACE, 'replay_requires_login_host_and_origin', 'The replay screen shows nothing without the login cookie, takes no token in the address, and refuses a foreign Host or Origin.'),
  attack(SURFACE, 'replay_session_id_cannot_leave_sessions_folder', 'A session id that is a path, an escape, a null byte or enormous finds nothing and reads nothing outside the project\'s sessions folder.'),
  attack(SURFACE, 'replay_log_text_cannot_become_markup', 'A command or reply in a session log that looks like HTML or script is shown on the replay screen as the characters it is: no element, no script, no request, no dialog, in a real browser.'),
  attack(SURFACE, 'replay_page_is_read_only_and_starts_nothing', 'The replay screen answers only GET, starts no session, runs no tool and writes no file, and has none of the live session\'s doors.'),
  attack(SURFACE, 'report_text_cannot_link_or_mention', 'A session report shows what a model wrote only as inert code, so a pull request cannot be made to link, mention or render it.'),

  // Team broker.
  attack(BROKER, 'modified_client_cannot_reach_denied_model', 'A modified client asking for a model the policy denies it never causes a call to that model.'),
  attack(BROKER, 'modified_client_never_receives_broker_key', 'No broker route, with good or bad input, answers with a credential the broker holds.'),
  attack(BROKER, 'denied_tool_call_stripped_from_reply', 'When the model asks for a tool the person may not use, the client never receives the call.'),
  attack(BROKER, 'modified_client_cannot_call_denied_server_tool', 'A modified client calling a denied server tool directly reaches nothing.'),
  attack(BROKER, 'modified_client_cannot_push_protected_ref_without_approval', 'Pushing a protected branch needs an approval, and asking again does not wear the broker down.'),
  attack(BROKER, 'requester_cannot_approve_own_request', 'Nobody can approve their own request: not from the same session, another session or a second login.'),
  attack(BROKER, 'stolen_token_refused_for_other_session_and_after_revoke', 'A session token used elsewhere, edited, or after its login was revoked is refused.'),
  attack(BROKER, 'forged_id_token_refused', 'An identity token signed with an attacker\'s key never becomes a login.'),
  attack(BROKER, 'old_policy_bundle_cannot_be_replayed', 'A looser, older policy bundle is refused and the newer one stays in force.'),
  attack(BROKER, 'budget_cannot_be_reset_by_client', 'New sessions and new logins do not reset the day\'s spending budget.'),
  attack(BROKER, 'memory_from_other_ou_never_returned', 'Team memory from another group is never returned, and nobody writes into a group they are not in.'),
  attack(BROKER, 'cut_audit_tail_caught_by_anchor', 'Cutting the end off the broker\'s audit chain is caught, because the anchor cannot go back and every refusal is in the chain.'),

  // Team audit (Phase 14).
  attack(BROKER, 'audit_read_by_non_reader', 'Someone whose policy does not name them as an audit reader gets nothing from any audit route, and the attempt is itself recorded.'),
  attack(BROKER, 'audit_read_by_session_token', 'The token a model-driven session holds cannot read the team audit; only a person login can.'),
  attack(BROKER, 'audit_reader_access_ends_with_policy', 'A person who stops being named as a reader in the signed policy is refused on their next request.'),
  attack(BROKER, 'audit_filter_injection', 'A search filter that is a pattern, an escape, a null byte, a repeated or unknown parameter, or enormous is refused or only ever compared, never interpreted.'),
  attack(BROKER, 'audit_export_row_edited', 'A row edited inside an audit export is found by the offline check, which names the row.'),
  attack(BROKER, 'audit_export_rows_removed_or_reordered', 'A row removed from, moved within or repeated in an audit export is found, even when the export header is changed to match.'),
  attack(BROKER, 'audit_export_tail_cut', 'Cutting the end off an audit export is found, whether the broker signed word about the old end is left in or taken out.'),
  attack(BROKER, 'audit_export_tail_extended_by_key_holder', 'Someone who holds the audit key and adds or rewrites rows still cannot make an export verify, because the new head was never signed by the broker.'),
  attack(BROKER, 'audit_export_row_swapped_by_key_holder', 'One row swapped for a genuine-looking one by someone who holds the audit key is found, because the rows after it no longer follow it.'),
  attack(BROKER, 'audit_checkpoint_forged', 'A checkpoint signed with another key, or edited to cover a different row, is refused, and so is a valid export checked with the wrong public key.'),
  attack(BROKER, 'audit_export_view_as_export', 'A filtered selection of rows is never reported as verified, and relabelling it as an export fails because rows are missing.'),
  attack(BROKER, 'audit_history_rewritten_after_pin', 'An export that ends before, or disagrees with, a checkpoint the auditor pinned on an earlier visit is refused.'),
  attack(BROKER, 'audit_pinned_key_replaced', 'If the broker audit-signing key is not the one the auditor was given or pinned, nothing more is pinned and the auditor is told.'),
  attack(BROKER, 'audit_checkpoint_file_edited', 'A checkpoint file edited by hand, or a chain cut under its checkpoints, stops the broker at start instead of being repaired.'),
  attack(BROKER, 'audit_tail_gap_or_repeat', 'A follower of the live audit, resuming from a row number, gets every later row exactly once and in order.'),
  attack(BROKER, 'audit_tail_outlives_login', 'A live audit stream ends when the login of the person following it has expired.'),
  attack(BROKER, 'audit_tail_follower_cap', 'At most eight people can follow the live audit at once, and a slot is given back when a follower leaves.'),
  attack(BROKER, 'audit_tail_slow_reader_dropped', 'A follower that stops reading is dropped, not buffered without limit, and the broker keeps writing.'),

  // Session log, memory and instructions (Phase 14).
  attack(LOG, 'laptop_audit_cut_tail_found_against_anchor', 'A session audit file with its end cut, rewritten, or made with another key is found by comparing it with the head the broker anchored for that session.'),
  attack(LOG, 'followed_log_forged', 'A forged record appended to a session log while the replay screen is following it turns the screen to refused, and none of the forged content is sent or shown.'),
  attack(LOG, 'followed_log_shortened_or_rewritten', 'A followed log that gets shorter, or whose already shown part changes while it still verifies, is refused.'),

  // The terminal and the local web page (Phase 14).
  attack(SURFACE, 'audit_screen_requires_login_host_and_origin', 'The auditor screen shows nothing without the login cookie, takes no token in the address, and refuses a foreign Host or Origin.'),
  attack(SURFACE, 'audit_screen_is_read_only', 'The auditor screen answers only GET and changes nothing on the broker or the machine.'),
  attack(SURFACE, 'audit_row_hidden_characters_written_out', 'A broker row with a right-to-left override, a zero-width space or a terminal escape reaches the auditor screen with each written out as visible text.'),
  attack(SURFACE, 'audit_row_html_injection', 'An approval whose action text looks like HTML or script is shown on the auditor screen as the characters it is: no element made, no script run, nothing fetched.'),

  // Editor extension.
  attack(EDITOR, 'editor_diff_shows_exact_bytes_written', 'The diff an editor shows for an approval matches the bytes that are written.'),
  attack(EDITOR, 'editor_diff_reveals_hidden_characters', 'Hidden characters in a change are shown to the person instead of being stripped from view.'),
  attack(EDITOR, 'editor_agent_cannot_read_files_or_start_terminals', 'A hostile agent behind the editor cannot make it read files or start terminals.'),
  attack(EDITOR, 'editor_agent_cannot_pick_allow_always', 'A hostile agent cannot make the editor offer or record "allow always".'),
  attack(EDITOR, 'editor_oversized_line_and_garbage_contained', 'An oversized line or garbage from the agent is contained without crashing or hanging the editor.'),
  attack(EDITOR, 'editor_reject_is_never_turned_into_allow', 'When the person does not allow a change, the editor never reports that they did.'),
  attack(EDITOR, 'editor_text_flood_contained', 'Text beyond one turn\'s limit is dropped and the person is told once.'),
  attack(EDITOR, 'editor_untrusted_folder_starts_nothing', 'In a folder VS Code has not been told to trust, the extension starts nothing.'),
  attack(EDITOR, 'editor_folder_settings_cannot_choose_binary_or_model_server', 'A folder\'s own settings file cannot choose which hn runs or which model server it talks to.'),
  attack(EDITOR, 'editor_installed_extension_not_run_in_untrusted_folder', 'The installed extension is not run at all in a folder that was not trusted.'),

  // GitHub Action.
  attack(ACTION, 'issue_text_cannot_close_the_untrusted_frame', 'Issue text is framed as data, and nothing in it can close that frame and pose as an instruction.'),
  attack(ACTION, 'issue_text_cannot_become_a_command', 'The gate step reads the event file and asks the API for the labeler\'s role; issue text is never run as a command.'),
  attack(ACTION, 'issue_text_is_untrusted_event_not_instruction', 'An issue is given to the agent as an untrusted event, and only the label from a maintainer is the instruction.'),
  attack(ACTION, 'issue_label_from_non_writer_runs_nothing', 'A label added by someone without write access runs nothing: no model call and no pull request.'),
  attack(ACTION, 'issue_planted_workflow_never_reaches_pull_request', 'When an issue steers the model into planting a workflow file, nothing of it reaches a pull request.'),
  attack(ACTION, 'github_token_never_reaches_hn', 'hn receives only the basics and what the workflow named, never the GitHub token or another secret.'),
  attack(ACTION, 'patch_with_symlink_submodule_binary_or_protected_path_refused', 'A patch that adds a link, a submodule or a large binary, or touches a protected path, is refused.'),
  attack(ACTION, 'patch_to_protected_path_pushes_nothing', 'A patch that touches a protected path pushes nothing, and the issue is told exactly what and why.'),
  attack(ACTION, 'agent_job_holds_no_write_token', 'Only the publish job holds a write token; the job that runs the model has none.'),
  attack(ACTION, 'workflow_never_pastes_issue_text_into_a_command', 'The workflow never pastes issue or user text into a command, and every action it uses is pinned to a commit.'),
  attack(KEYS, 'roster_signed_by_signing_key', 'A key roster signed by a signing key, even a trusted one, is refused: only the offline root may change which keys are trusted, so a leaked signing key cannot add its own key or revoke the good ones.'),
  attack(KEYS, 'roster_forged_or_edited', 'A key roster that claims the name of the root but is signed by someone else, or whose keys were edited after signing, is refused.'),
  attack(KEYS, 'roster_replayed_older', 'An older key roster, or a different one with the same serial, is refused, so an old roster cannot be put back to bring a key back.'),
  attack(KEYS, 'roster_wrong_purpose', 'A roster made for one purpose (policy, release or audit) is refused where another is asked for.'),
  attack(KEYS, 'roster_unrevokes_key', 'A revoked key can never be trusted again, by its id or by its public key under a new id, and a later roster that simply leaves it out keeps it revoked.'),
  attack(KEYS, 'trust_record_edited', 'Editing, truncating or moving the record of which keys a machine trusts stops everything instead of falling back to the keys the package shipped, which would forget a revocation.'),
  attack(KEYS, 'revoked_release_key_refused', 'After a root-signed revocation, an update archive, an installed copy and a sandbox helper manifest signed by the revoked release key are all refused, and hn doctor says what to do.'),
  attack(KEYS, 'revoked_policy_key_refused', 'A leaked policy key that signs a looser policy with a higher serial is followed before the revocation and refused by both the broker and the laptop after it.'),
  attack(KEYS, 'policy_roster_other_root_refused', 'A laptop refuses a key roster the broker serves that is older, signed by a signing key, or signed by a root it did not pin at login.'),
  attack(KEYS, 'policy_root_not_taken_from_known_broker', 'A broker the laptop is already logged in to cannot hand it a new root key later: the root is taken only at the first login.'),
  attack(KEYS, 'audit_checkpoint_after_retirement', 'A retired audit-signing key signing a checkpoint for a row after its retirement is refused by the offline check, and so is a new key signing for rows before it began.'),
  attack(KEYS, 'audit_checkpoint_revoked_key_after_row', 'Someone with a leaked audit key who extends the chain and signs the new head with it cannot make an export verify once the key is revoked after a row; its older checkpoints still count as history.'),
  attack(KEYS, 'audit_roster_stale_in_bundle', 'An older roster placed inside an export, from before a revocation, does not bring the revoked audit key back: an auditor keeps the newest roster they have seen.'),
];

export const attackNames = (): readonly string[] => ATTACKS.map((entry) => entry.name);
