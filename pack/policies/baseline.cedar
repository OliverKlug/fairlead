// Fairlead baseline pack (rule ids F-DEF / F-SEQ / F-SUB / F-AUTO).
// Deny-by-default: forbid wins, then permit, else deny.
// Cap names exist (net.egress, secrets.read, mcp.write) but live adapters pass an empty
// granted_caps. F-DEF-02, F-DEF-03, and F-DEF-04 are unconditional on that path.
// A later grant must not treat net.egress as clearing an MCP write: F-DEF-07's exemption
// is net.egress even when mcp_is_write is the reason it matched. F-DEF-04 still wants mcp.write.
// Provenance tags: user | rules | repo-code | repo-doc | mcp | web | shell | subagent
// (adapter may also emit mcp:<server>; policies match the coarse "mcp"/"web" tags.)

@id("F-DEF-01")
forbid (
  principal,
  action in [Fairlead::Action::"FileWrite", Fairlead::Action::"Shell"],
  resource
)
when { context.path_is_sensitive };

@id("F-DEF-03")
forbid (
  principal,
  action in [Fairlead::Action::"Shell", Fairlead::Action::"McpCall", Fairlead::Action::"Fetch", Fairlead::Action::"FileWrite"],
  resource
)
when {
  context.command_looks_like_network &&
  !context.granted_caps.contains("net.egress")
};

@id("F-DEF-02")
forbid (
  principal,
  action == Fairlead::Action::"FileRead",
  resource
)
when {
  context.path_is_sensitive &&
  !context.granted_caps.contains("secrets.read")
};

@id("F-DEF-04")
forbid (
  principal,
  action == Fairlead::Action::"McpCall",
  resource
)
when {
  context.mcp_is_write &&
  !context.granted_caps.contains("mcp.write")
};

@id("F-DEF-05")
forbid (
  principal,
  action == Fairlead::Action::"Shell",
  resource
)
when {
  context.command_looks_like_network &&
  context.provenance.containsAny(["web", "mcp"]) &&
  !context.granted_caps.contains("net.egress")
};

// Second id beside a classifier deny. Not a reason by itself: a live adapter has no grant,
// so a network command already hits F-DEF-03 and a write-shaped MCP call already hits F-DEF-04.
@id("F-DEF-07")
forbid (
  principal,
  action in [Fairlead::Action::"Shell", Fairlead::Action::"Fetch", Fairlead::Action::"McpCall"],
  resource
)
when {
  context.session.touched_secrets &&
  (context.command_looks_like_network || context.mcp_is_write) &&
  !context.granted_caps.contains("net.egress")
};

@id("F-DEF-08")
forbid (
  principal,
  action == Fairlead::Action::"Shell",
  resource
)
when {
  (context.session.saw_untrusted_web || context.session.saw_mcp_untrusted) &&
  context.command_looks_like_network &&
  !context.granted_caps.contains("net.egress")
};

// Goal 10. The Controller sets the flag when the session dir holds a quarantined value.
// The call's bytes are not the predicate: a command that contains neither the handle nor
// the title is still this forbid (live: python3 -c "print(1)" and ls were F-DEF-06).
// Not exempted by net.egress. Attacker-chosen titles stay attacker-chosen. No record,
// and a boring shell stays F-DEF-06. Ceiling: one handles.jsonl taints every conversation
// in that session dir, including ls and rg, until the file is gone.
@id("F-Q-ARG")
forbid (
  principal,
  action in [
    Fairlead::Action::"Shell",
    Fairlead::Action::"Fetch",
    Fairlead::Action::"McpCall",
    Fairlead::Action::"FileWrite"
  ],
  resource
)
when {
  context has argument_from_untrusted &&
  context.argument_from_untrusted
};

@id("F-SUB-03")
forbid (
  principal,
  action,
  resource
)
when {
  context.session.subagent_active &&
  context.command_looks_like_network &&
  !context.parent_caps.contains("net.egress")
};

@id("F-SUB-03b")
forbid (
  principal,
  action == Fairlead::Action::"McpCall",
  resource
)
when {
  context.session.subagent_active &&
  context.mcp_is_write &&
  !context.parent_caps.contains("mcp.write")
};

@id("F-SUB-03c")
forbid (
  principal,
  action == Fairlead::Action::"FileRead",
  resource
)
when {
  context.session.subagent_active &&
  context.path_is_sensitive &&
  !context.parent_caps.contains("secrets.read")
};

@id("F-DEF-06")
permit (
  principal,
  action == Fairlead::Action::"Shell",
  resource
)
when {
  context.argv0_is_boring &&
  !context.command_looks_like_network &&
  !context.path_is_sensitive
};

// python/node/pytest stay in the boring list. Forbid wins, including
// python -m pytest/unittest/doctest. Those stay ScriptInspect::Clean, so the
// sentence is F-DEF-09, not F-DEF-03. npm, npx, cargo, and go still run
// repository code. tsc typechecks and does not run the program.
@id("F-DEF-09")
forbid (
  principal,
  action == Fairlead::Action::"Shell",
  resource
)
when { context has interpreter_exec && context.interpreter_exec };

@id("F-AUTO-read")
permit (
  principal,
  action == Fairlead::Action::"FileRead",
  resource
)
when { !context.path_is_sensitive };

@id("F-AUTO-write")
permit (
  principal,
  action == Fairlead::Action::"FileWrite",
  resource
)
when { !context.path_is_sensitive };

// Named read only. A tool whose name misses the write-verb list is not a read.
// drop_table has no permit and default-denies. mcp_is_write stays a second belt (F-DEF-04).
@id("F-AUTO-mcp-read")
permit (
  principal,
  action == Fairlead::Action::"McpCall",
  resource
)
when {
  context.tool_name == "get_latest_issue" ||
  context.tool_name like "mcp__*__get_latest_issue"
};
