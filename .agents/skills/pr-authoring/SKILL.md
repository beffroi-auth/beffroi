---
name: pr-authoring
description: >
  Take an issue of this repository to a pull request that is ready to merge
  when it is opened, and to the documentation pull request that goes with it.
  Use when the user asks to fix an issue, to build a story of the spike, to
  refactor, or to make any other change to this repository ("fais l'issue",
  "ouvre la PR"), and read it before writing the first line of code.
---

# From an issue to a pull request

`AGENTS.md` holds the rules: « Working on an issue » for the worktree, the branch, the commit and the checks, then « Conventions », « SOLID » and « Tests » for the code itself. This skill is the order in which they apply, and what the pull request says.

## Before writing code

- Read the issue, its discussion and the README of the spike it belongs to (`../spikes/`). What the spike does not cover is not built, even when it is easy (decision 0005): it becomes an issue on the spike that needs it.
- Read the decisions the change touches (`../docs/decisions/`), and the specification of the package when it has one (`src/*/spec/`): the code conforms to it, or the document changes first, in a commit of its own with its reason.
- Work in a worktree of the scratchpad, on a branch `<type>/<issue>-<slug>` taken from `origin/HEAD` (`AGENTS.md`). When an older maintained branch has the same defect, ask the user which branch the fix targets; the newer ones get it by `beffroi-merge-up`.
- Re-derive the problem from the code, whatever the issue says it is, and reproduce it with a failing test before changing anything: a fix for a failure nobody saw cannot be verified.

## While working

- The test first, then the code, then the whole suite of the touched package. Every test has the form of `AGENTS.md`, « Tests ».
- Hold the code to `AGENTS.md`, « SOLID », as it is written, not at review: a new kind is a class added, a block written twice becomes a use case or a value object, an interface stays per capability.
- Keep the diff to the issue. What you find outside it is reported, or becomes an issue of its own.
- Everything is in English: code, comments, commits, the pull request.

## Before opening it

- Run the checks of `AGENTS.md`, « Before the pull request »: `castor prepare-pr`, `castor phpunit`, `castor phpstan` and `castor deptrac`; `castor app-phpunit` when the change touches the application or what its kernel wires; `castor infect --diff` when the change is a rule; `castor config-reference` when a configuration tree changes. Read the summary each one prints, not only its exit status.
- Revert-verify each new test: put the source back as it is on the base, keep the tests, and watch each new test fail for the reason it names. A test that also passes on the base protects existing behaviour; it does not prove the change.
- Review your own diff as a reviewer would, against « Conventions », « SOLID » and « Tests », and apply what you find. A finding is not left in the description as work for later.
- Shape the commits: `type(scope): what it does, lowercase, no final period (issue #N)`, each message matching its diff; a change of a specification in a commit of its own, before the code that follows it.

## Opening it

- Pushing and opening the pull request are outward actions: ask the user first, unless they asked for the pull request.
- `git push -u origin <branch>`, then `gh pr create --head <branch> --base <base>`, always with `--head`: another session can move the current branch of a shared checkout.
- The title is the commit subject when there is one commit, and says the same thing when there are more. The body, in English, has the sections of the pull requests of this repository:
  - `## What`: what the change does and why, for a reader who never saw the issue, the rules it applies with their sections, then `Closes #N.` and `Part of #<epic>.`;
  - `## Specification`, when a package specification changes: its sections and the rules added or touched;
  - `## Checklist`: each check run with its result and the figures it printed (tests, mutants killed), each check not run with its reason, and the conventions the change could break, each answered: a synchronous write, a secret drawn or compared, a boolean from a third party, a user-facing string, the security defaults of decision 0006.
- Once it is open: the status comment of a long-running issue, one, edited in place; every red CI job accounted for, caused by the change or there before it.

## The documentation pull request

- In the parent repository, on a branch `docs/<issue>-<slug>`, with the skill `../.agents/skills/docs-authoring/SKILL.md`: the journal row of the spike, and the pages the change makes false. A session started here does not list that skill; it reads it by that path.
- Its body names the code pull request whose pages it brings in line.
