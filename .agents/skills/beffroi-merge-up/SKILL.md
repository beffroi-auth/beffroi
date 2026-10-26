---
name: beffroi-merge-up
description: >
  Merge each maintained branch of the Beffroi monorepo into the next one,
  oldest to newest, resolving the conflicts and running the checks between two
  merges, and finish the merge-up pull request a release opens. Use it in this
  repository instead of any generic merge-up skill, when the user says "merge
  up", "merge-up", "cascade merge", "sync the branches", or when a change
  landed on a maintained branch older than the default one.
---

# Merging up the maintained branches

A change made on a maintained branch reaches the newer ones by a merge, each branch into the next, the oldest first. Nothing is merged the other way.

## The branches

- The maintained branches are the branches of `origin` whose name matches the first pattern of `origins` in `.gitsplit.yml`, `^\d+\.\d+\.x$`. Sorted by version, oldest first:

  ```bash
  git fetch origin
  git branch -r --list 'origin/*.*.x' | sed 's|^ *origin/||' | grep -E '^[0-9]+\.[0-9]+\.x$' | sort -V
  ```

- The newest is the default branch, `origin/HEAD`: a release creates the next branch, and `auto-switch-default-branch.yml` moves the default to it.
- With a single maintained branch there is nothing to merge: say so and stop.
- Show the list and wait for the user to confirm it; they may leave a branch out.

## What a release does already

- Closing a milestone named after a version runs `release-on-milestone-closed.yml`, and laminas/automatic-releases opens a pull request that merges the released branch into the next one. Look for it before merging by hand: `gh pr list --state open --search 'Merge release in:title'`.
- When it is open, that pull request is the merge of its pair. Resolve its conflicts on its own branch, run the checks below, and merge it with a merge commit (`gh pr merge <N> --merge`) once the user agrees. The same pair is not merged a second time by hand.

## Where the merge happens

- In a worktree of this repository under the session scratchpad, detached: `git worktree add --detach <scratchpad>/merge-up origin/<TARGET>`. The shared checkout at `~/Projects/idp/code` belongs to whoever is using it, and a branch checked out in a worktree is locked for every other one; a detached worktree pushes with an explicit refspec.
- The worktree is clean before the first merge: `git status --porcelain` prints nothing.

## Each pair, oldest first

1. **Merge.** `git switch --detach origin/<TARGET>`, then `git merge --no-ff --no-edit origin/<SOURCE>`. Already up to date: the next pair. Merged without a conflict: the checks. Conflicts: resolve them first.
2. **Resolve.** `git diff --name-only --diff-filter=U` lists the files. Resolve each one as the table below says, `git add` it, and `git commit --no-edit` once none is left. Show `git diff HEAD^1 HEAD`, what the merge brings to the TARGET, and wait for the user to confirm the resolution.

| The file | Its resolution |
|---|---|
| A `composer.json`, of the root, of a package or of `apps/op` | The TARGET's constraints on PHP, Symfony and the dependencies, which a newer branch may raise; the packages keep requiring one another at `self.version` |
| `.gitsplit.yml` | The TARGET's targets, since a newer branch may split more packages |
| `.ci-tools/phpstan-baseline.neon` | Neither side by hand: the TARGET's version, then `castor phpstan-baseline` once the merge compiles |
| `apps/op/config/reference.php`, `apps/op/config/schema.json` | Generated again by `castor config-reference-fix` |
| A migration of `src/symfony/migrations/` | Both sides kept, each migration in its own class |
| A catalogue of `src/symfony/translations/` | The units of both sides |
| A specification of `src/*/spec/` | The rules of both sides, and the code following them: the specification is the law of its package |
| Anything else | By meaning, both changes kept; when the two cannot both hold, ask the user |

3. **Check.** In the worktree, with `</dev/null` when there is no terminal:

   ```bash
   composer install
   (cd apps/op && composer install)
   castor mago-lint
   castor mago-format
   castor rector
   castor phpstan
   castor deptrac
   castor phpunit
   castor config-reference
   castor app-phpunit   # on the PostgreSQL a running stack publishes; say so when there is none
   ```

   A check that fails is run again on the TARGET before the merge. When it fails there too, it is reported and left alone. When only the merge fails it, the fix is a commit of its own on top of the merge, and the checks run again.
4. **Push.** Show `git log --oneline origin/<TARGET>..HEAD` and each check with its result, and wait for the user's go: a maintained branch is mirrored into the read-only repositories as soon as it is pushed (`gitsplit.yml`). Then `git push origin HEAD:<TARGET>`. A refused push means the branch moved: fetch, merge again on its new tip, never force.
5. **Next.** The next pair starts from the TARGET just pushed.

## After the last pair

- One line per pair, up to date, merged, or merged with conflicts, and the checks with their results, those not run included.
- The push of each branch starts the CI and the split: follow them with `gh run list --branch <TARGET> --limit 5` until they end, and account for every red job.

## Never

- A force-push, a rewritten maintained branch, `--no-verify`.
- A newer branch merged into an older one.
- A push the user did not agree to.
