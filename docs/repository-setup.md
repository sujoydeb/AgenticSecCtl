# Repository Setup Procedure (not executed)

| | |
|---|---|
| Version | 0.1 (procedure draft; advances gap G4 in `docs/reviewgap.md`) |
| Depends on | `docs/ci-cd-pipeline.md` v0.4 (Sections 5, 6, 12), `docs/governance.md` v0.3, `.github/CODEOWNERS.example`, `.github/workflows/docs-check.yml` |
| Status | **Nothing in this document has been run.** No remote repository exists and the user declined creating or publishing one on 2026-11-22. The commands are an untested outline for someone with the right rights to adapt. Setting names and endpoints are **[VERIFY]** against current GitHub documentation before use. |

## 1. Preconditions

- A decision on where the repository lives (customer input CI-12, ADR on tooling) and who administers it.
- Real teams for each code-owner role in `.github/CODEOWNERS.example` (governance document role glossary).
- Agreement on break-glass administration (CTL-23).

## 2. Steps (outline)

| Step | What | How (untested) | Check afterwards |
|---|---|---|---|
| 1 | Create the private repository under the organisation | `gh repo create ORG/agenticsecctl --private` **[VERIFY]** | Repository is private; default branch is `main` |
| 2 | Push the existing history | `git remote add origin ...` then `git push -u origin main` | Commit hashes match local |
| 3 | Copy `.github/CODEOWNERS.example` to `.github/CODEOWNERS`, replace placeholders | Pull request, reviewed by security architect | GitHub shows no unknown-owner warnings |
| 4 | Protect `main`: required status check `docs-check`, no force push, linear history, dismiss stale approvals, two reviewers for security-relevant paths, restrict deletion | Repository settings or `gh api` branch protection call **[VERIFY]** | Try a direct push as a non-admin: it must be refused |
| 5 | Require signed commits if the chosen setup supports it | Branch protection option **[VERIFY availability]** | An unsigned test commit is refused |
| 6 | Restrict Actions: allow only actions pinned by SHA, set workflow permissions to read by default | Organisation or repository settings **[VERIFY]** | `docs-check` still runs |
| 7 | Create environments (staging, production) with required reviewers, once product workflows exist | Settings | Deployment job waits for approval |
| 8 | Turn on secret scanning, push protection and dependency alerts as available **[VERIFY]** | Settings | Test with a dummy token string, never a real one |
| 9 | Enable Dependabot version updates using `.github/dependabot.yml` | Already in repository | First update PRs arrive and are reviewed, not auto-merged |
| 10 | Run `docs-check` on a pull request and fix whatever fails (the workflow has never run) | Open a trivial PR | Green check; record the result in the ci-cd document |

## 3. Acceptance

Done only when steps 3 to 6 and 10 are observed working (not just configured), the evidence is attached to the governance review log, and gap G4 is changed accordingly. Until then it stays open.
