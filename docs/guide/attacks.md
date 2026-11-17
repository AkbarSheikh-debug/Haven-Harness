# The attack catalog

Every attack below has a test with its name in the title. **Pass means the effect did not happen**, judged on the far
side (a canary file that was never written, a listener that saw no connection, a remote repository with no new ref, a
chain that verifies), never by the model's or the system's own words. A test suite with a red attack does not ship.

The list is checked by `packages/surfaces/test/attacks.test.ts`: a named attack without a test fails the build.

| Attack | Test |
|---|---|
| `agents_md_symlink_to_secret_not_loaded` | [packages/operations/test/safe-files.test.ts](../../packages/operations/test/safe-files.test.ts) |
| `approval_invalid_after_script_edit` | [packages/security/test/approval.test.ts](../../packages/security/test/approval.test.ts) |
| `bidi_and_overwrite_approval_escaped` | [packages/security/test/approval.test.ts](../../packages/security/test/approval.test.ts) |
| `box_job_cannot_use_tool_socket` | [packages/tools/test/jobs.test.ts](../../packages/tools/test/jobs.test.ts) |
| `budget_cannot_be_reset_by_client` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `call_tool_unwrapped_before_gate` | [packages/tools/test/tools.test.ts](../../packages/tools/test/tools.test.ts) |
| `card_shows_exact_stored_bytes` | [packages/memory/test/cards.test.ts](../../packages/memory/test/cards.test.ts) |
| `checkpoint_excludes_secrets` | [packages/operations/test/checkpoints.test.ts](../../packages/operations/test/checkpoints.test.ts) |
| `ci_workflow_write_requires_human` | [packages/security/test/gate-modes.test.ts](../../packages/security/test/gate-modes.test.ts) |
| `control_file_hash_change_reprompts` | [packages/context/test/instructions.test.ts](../../packages/context/test/instructions.test.ts) |
| `cut_audit_tail_caught_by_anchor` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `daily_note_web_line_not_autoloaded` | [packages/memory/test/snapshot.test.ts](../../packages/memory/test/snapshot.test.ts) |
| `deep_agents_md_cannot_evict_user_rules` | [packages/context/test/instructions.test.ts](../../packages/context/test/instructions.test.ts) |
| `denied_tool_call_stripped_from_reply` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `devcontainer_initialize_command_never_runs` | [packages/surfaces/test/recipes.test.ts](../../packages/surfaces/test/recipes.test.ts) |
| `disk_quota_blocks_bind_mount_fill` | [packages/surfaces/test/attacks.test.ts](../../packages/surfaces/test/attacks.test.ts) |
| `dns_subdomain_exfil_blocked_pre_resolve` | [packages/operations/test/web.test.ts](../../packages/operations/test/web.test.ts) |
| `dockerfile_context_excludes_secrets` | [packages/surfaces/test/recipes.test.ts](../../packages/surfaces/test/recipes.test.ts) |
| `dotenv_case_variants_masked` | [packages/surfaces/test/attacks.test.ts](../../packages/surfaces/test/attacks.test.ts) |
| `exit_plan_mode_requires_human` | [packages/tools/test/planning-tools.test.ts](../../packages/tools/test/planning-tools.test.ts) |
| `external_provider_refused_in_yolo` | [packages/delegate/test/external.test.ts](../../packages/delegate/test/external.test.ts) |
| `external_sandbox_refused_on_workstation` | [packages/surfaces/test/sandbox-door.test.ts](../../packages/surfaces/test/sandbox-door.test.ts) |
| `forged_id_token_refused` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `forged_log_grants_nothing` | [packages/session/test/crash.test.ts](../../packages/session/test/crash.test.ts) |
| `git_dir_rename_cannot_replace_config` | [packages/surfaces/test/attacks.test.ts](../../packages/surfaces/test/attacks.test.ts) |
| `git_history_secret_not_readable_in_box` | [packages/surfaces/test/sandbox-door.test.ts](../../packages/surfaces/test/sandbox-door.test.ts) |
| `global_git_filter_not_invoked` | [packages/surfaces/test/attacks.test.ts](../../packages/surfaces/test/attacks.test.ts) |
| `guardian_cannot_approve_external` | [packages/security/test/gate-v2.test.ts](../../packages/security/test/gate-v2.test.ts) |
| `handoff_keeps_taint` | [packages/surfaces/test/handoff.test.ts](../../packages/surfaces/test/handoff.test.ts) |
| `hardlink_to_denied_file_refused` | [packages/operations/test/safe-files.test.ts](../../packages/operations/test/safe-files.test.ts) |
| `harness_exec_requires_gate_below_tier3` | [packages/tools/test/harness-exec.test.ts](../../packages/tools/test/harness-exec.test.ts) |
| `host_exec_manifest_blocks_import` | [packages/operations/test/handback.test.ts](../../packages/operations/test/handback.test.ts) |
| `hostile_image_cannot_fake_canary` | [packages/operations/test/verifier.test.ts](../../packages/operations/test/verifier.test.ts) |
| `image_recipe_edit_requires_human_on_resume` | [packages/surfaces/test/recipes.test.ts](../../packages/surfaces/test/recipes.test.ts) |
| `linked_worktree_gitfile_rewrite_rejected` | [packages/operations/test/handback.test.ts](../../packages/operations/test/handback.test.ts) |
| `markdown_image_never_fetched` | [packages/surfaces/test/serve.test.ts](../../packages/surfaces/test/serve.test.ts) |
| `mcp_sampling_denied` | [packages/tools/test/mcp.test.ts](../../packages/tools/test/mcp.test.ts) |
| `member_cannot_move_main_ref` | [packages/orchestrate/test/team.test.ts](../../packages/orchestrate/test/team.test.ts) |
| `memory_from_other_ou_never_returned` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `modified_client_cannot_call_denied_server_tool` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `modified_client_cannot_push_protected_ref_without_approval` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `modified_client_cannot_reach_denied_model` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `modified_client_never_receives_broker_key` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `nested_gitdir_and_bare_repo_rejected_on_import` | [packages/operations/test/handback.test.ts](../../packages/operations/test/handback.test.ts) |
| `old_policy_bundle_cannot_be_replayed` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `option_click_not_user_origin` | [packages/tools/test/planning-tools.test.ts](../../packages/tools/test/planning-tools.test.ts) |
| `osc52_and_osc8_stripped_all_doors` | [packages/surfaces/test/doors.test.ts](../../packages/surfaces/test/doors.test.ts) |
| `parent_session_grant_not_inherited` | [packages/security/test/policy.test.ts](../../packages/security/test/policy.test.ts) |
| `path_encoded_exfil_blocked_under_taint` | [packages/security/test/egress.test.ts](../../packages/security/test/egress.test.ts) |
| `plugin_backend_cannot_claim_tier` | [packages/operations/test/backends.test.ts](../../packages/operations/test/backends.test.ts) |
| `prepare_cannot_publish_or_reach_engine_api` | [packages/operations/test/prepare.test.ts](../../packages/operations/test/prepare.test.ts) |
| `proto_pollution_config_cannot_widen` | [packages/surfaces/test/attacks.test.ts](../../packages/surfaces/test/attacks.test.ts) |
| `read_image_decompression_bomb_contained` | [packages/tools/test/read-image.test.ts](../../packages/tools/test/read-image.test.ts) |
| `recall_gates_ignore_injected_queries` | [packages/memory/test/dream.test.ts](../../packages/memory/test/dream.test.ts) |
| `recursive_hn_cannot_reset_taint` | [packages/surfaces/test/sandbox-door.test.ts](../../packages/surfaces/test/sandbox-door.test.ts) |
| `redirect_revalidated` | [packages/operations/test/web.test.ts](../../packages/operations/test/web.test.ts) |
| `requester_cannot_approve_own_request` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `rollback_refuses_while_box_alive` | [packages/operations/test/checkpoints.test.ts](../../packages/operations/test/checkpoints.test.ts) |
| `rollback_reports_skipped_paths` | [packages/operations/test/checkpoints.test.ts](../../packages/operations/test/checkpoints.test.ts) |
| `scan_redos_times_out_denied` | [packages/security/test/threat.test.ts](../../packages/security/test/threat.test.ts) |
| `serve_rejects_foreign_origin_and_rebinding` | [packages/surfaces/test/serve.test.ts](../../packages/surfaces/test/serve.test.ts) |
| `spawn_never_uses_cwd_binary_windows` | [packages/surfaces/test/attacks.test.ts](../../packages/surfaces/test/attacks.test.ts) |
| `ssrf_metadata_and_loopback_blocked` | [packages/operations/test/web.test.ts](../../packages/operations/test/web.test.ts) |
| `stdio_mcp_env_allowlist` | [packages/tools/test/mcp.test.ts](../../packages/tools/test/mcp.test.ts) |
| `steer_ipc_rejected_without_token` | [packages/surfaces/test/control.test.ts](../../packages/surfaces/test/control.test.ts) |
| `stolen_token_refused_for_other_session_and_after_revoke` | [packages/broker/test/modified-client.test.ts](../../packages/broker/test/modified-client.test.ts) |
| `submodule_fsmonitor_not_executed_after_session` | [packages/surfaces/test/attacks.test.ts](../../packages/surfaces/test/attacks.test.ts) |
| `symlink_swap_during_read_write` | [packages/operations/test/safe-files.test.ts](../../packages/operations/test/safe-files.test.ts) |
| `tainted_schedule_requires_human` | [packages/surfaces/test/schedules.test.ts](../../packages/surfaces/test/schedules.test.ts) |
| `terminal_reply_cannot_answer_approval` | [packages/surfaces/test/attacks.test.ts](../../packages/surfaces/test/attacks.test.ts) |
| `unmarked_repo_counts_private` | [packages/security/test/taint.test.ts](../../packages/security/test/taint.test.ts) |
| `vm_escape_refused_below_tier3` | [packages/orchestrate/test/workflow.test.ts](../../packages/orchestrate/test/workflow.test.ts) |
| `web_to_file_to_read_stays_tainted` | [packages/security/test/taint.test.ts](../../packages/security/test/taint.test.ts) |
| `yolo_without_sandbox` | [packages/security/test/gate-modes.test.ts](../../packages/security/test/gate-modes.test.ts) |
| `zstd_bomb_rejected` | [packages/session/test/log.test.ts](../../packages/session/test/log.test.ts) |
