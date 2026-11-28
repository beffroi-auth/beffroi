# Contributing

Thank you for looking at Beffroi. The project is young: the scope is narrow on purpose, and the decisions that shape it are settled. Read `AGENTS.md` for the conventions.

## Before opening a pull request

- Open or pick an issue first; the milestones say what is in scope now.
- Run `castor prepare-pr` and `castor phpunit`. CI runs the same tools on PHP 8.5, and the tests on 8.4 and 8.6 as well.
- A node added, renamed or re-worded in the configuration of the provider (the `beffroi:` tree): run `castor config-reference-fix` and commit `apps/beffroi/config/reference.php` and `apps/beffroi/config/schema.json` with it. CI checks them.
- Name tests after the specification section they verify.
- Comment only what the names and the code cannot say: the types PHP cannot express, `@throws`, the section a class implements, a reason someone would otherwise undo. No comment that restates a name, no design narrative, no history.
- Do not add a security option. Security defaults are code; a legitimate blocked case gets a named, bounded exception, discussed in an issue first.
- Do not add a synchronous write unless the protocol needs its result in the same request; list any exception in `apps/beffroi/config/packages/messenger.yaml` with its reason.
- Translate every user-facing string (`en`, `fr`).

## Commits

Conventional prefixes (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`), one topic per commit, English.

## Reporting a vulnerability

See `SECURITY.md`. Never in a public issue.
