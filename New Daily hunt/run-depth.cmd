@echo off
REM ============================================================================
REM  DEPTH PASS - ADD-ON. Runs AFTER the breadth hunt (daily-single) finishes.
REM  Reads breadth output in reports-noskill\, runs the modules in depth-modules\,
REM  writes reports-noskill\depth-findings.json.
REM  It does NOT modify the breadth hunt (daily-single.txt) or its report.
REM  If this step fails or is skipped, you simply keep the breadth report = today.
REM
REM  Mirrors the proven headless invocation (inline opus, no subagents - they
REM  cannot reach MCP headless). If your other runners call bin\claude.exe
REM  directly, point CLAUDE_BIN at the same path.
REM ============================================================================

cd /d D:\Vidhya\New Daily hunt

set CLAUDE_BIN=claude

%CLAUDE_BIN% -p --model opus --mcp-config .mcp.json --strict-mcp-config --permission-mode bypassPermissions < noskill-prompts\depth-pass.txt

REM Schedule this as a SECOND step right after the breadth hunt completes
REM (or add this line to the end of the breadth runner).
