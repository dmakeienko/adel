# Release automation: GitHub App for release-please

This guide sets up a GitHub App that release-please uses to open and update
the release PR, and the repository settings that keep release notes clean.

## Why a GitHub App?

release-please opens the release PR (`chore(main): release X.Y.Z`). If it
authenticates with the built-in `GITHUB_TOKEN`, the PR is authored by
`github-actions[bot]`, and GitHub does **not** run workflows for events
created with `GITHUB_TOKEN`. Every release PR then shows
**"2 workflows awaiting approval"** (CI and Security end in `action_required`)
and someone has to click *Approve and run* by hand.

A GitHub App installation token has none of these limits. The release PR is
authored by `<your-app>[bot]` and CI runs on it like on any other PR.

| Option | Triggers CI | Expires | Tied to a person | Scope |
|---|---|---|---|---|
| `GITHUB_TOKEN` | no (needs manual approval) | per job | no | current repo |
| Personal access token | yes | you rotate it by hand | **yes** (your account) | everything you can access |
| **GitHub App** (used here) | **yes** | **1 hour, minted per run** | no | only repos the App is installed on, only the permissions you grant |

## Overview

1. Create the App (≈5 min).
2. Generate a private key and install the App on `dmakeienko/adel`.
3. Store the Client ID and private key as repository secrets.
4. Switch the repository to squash merges (this fixes the duplicate changelog entries).
5. Recreate the open release PR and verify.

The workflow already contains the integration (`.github/workflows/release.yml`).
**Until the secrets exist it falls back to `GITHUB_TOKEN`**, so merging the
workflow changes before setting up the App is safe. You keep the current
behaviour (manual approval) until the secrets are added.

---

## 1. Create the GitHub App

1. Open <https://github.com/settings/apps/new>
   (avatar → **Settings** → **Developer settings** → **GitHub Apps** →
   **New GitHub App**).
2. Fill in:

   | Field | Value |
   |---|---|
   | **GitHub App name** | `adel-release-bot`. Names are global, so add a suffix if it's taken. This name shows as the PR author: `adel-release-bot[bot]`. |
   | **Description** | `Opens release-please PRs for dmakeienko/adel` (optional) |
   | **Homepage URL** | `https://github.com/dmakeienko/adel` |
   | **Callback URL** | leave empty |
   | **Expire user authorization tokens** | leave as is (not used) |
   | **Request user authorization (OAuth) during installation** | unchecked |
   | **Enable Device Flow** | unchecked |
   | **Setup URL** | leave empty |
   | **Webhook → Active** | **uncheck**. The App only mints tokens and needs no events. |

3. **Permissions → Repository permissions.** Set exactly these and leave
   everything else at *No access*:

   | Permission | Access | Why |
   |---|---|---|
   | **Contents** | Read and write | push the `release-please--branches--main` branch, create tags and GitHub releases |
   | **Pull requests** | Read and write | open/update the release PR |
   | **Issues** | Read and write | add/remove the `autorelease: pending` / `autorelease: tagged` labels (labels are an Issues API) |
   | **Metadata** | Read-only | mandatory, selected automatically |

   Do **not** grant *Workflows*. The release PR only touches `CHANGELOG.md`,
   `.release-please-manifest.json` and `charts/adel/Chart.yaml`, never files
   under `.github/workflows/`.

4. **Organization / Account permissions:** none.
5. **Subscribe to events:** none (webhook is disabled anyway).
6. **Where can this GitHub App be installed?** → **Only on this account**.
7. Click **Create GitHub App**.

## 2. Client ID, private key, installation

On the App's settings page (`https://github.com/settings/apps/<app-name>`):

1. **Copy the Client ID** from the *About* section (it looks like
   `Iv23liXXXXXXXXXXXXXX`). The workflow uses the Client ID, not the numeric
   *App ID*: `actions/create-github-app-token` v3 deprecates `app-id`.
2. Scroll to **Private keys** → **Generate a private key**. A file named
   `<app-name>.<date>.private-key.pem` downloads. This key lets anyone mint
   tokens for the App, so treat it like a password.
3. In the left sidebar click **Install App** → **Install** next to your account
   → choose **Only select repositories** → pick **adel** → **Install**.

> If you change the App's permissions later, GitHub asks the installation to
> accept the new permissions: **Settings → Applications → Installed GitHub
> Apps → adel-release-bot → Review request**. Until you accept, the token keeps
> the old permissions.

## 3. Add the repository secrets

The workflow expects two **Actions** secrets (not Dependabot or Codespaces
secrets):

| Secret | Value |
|---|---|
| `RELEASE_APP_CLIENT_ID` | the Client ID from step 2.1 |
| `RELEASE_APP_PRIVATE_KEY` | the **entire** content of the `.pem` file, including the `-----BEGIN RSA PRIVATE KEY-----` / `-----END RSA PRIVATE KEY-----` lines |

With the GitHub CLI (reads the key straight from the file, so there are no copy/paste
mistakes):

```bash
gh secret set RELEASE_APP_CLIENT_ID   --repo dmakeienko/adel --body 'Iv23liXXXXXXXXXXXXXX'
gh secret set RELEASE_APP_PRIVATE_KEY --repo dmakeienko/adel < ~/Downloads/adel-release-bot.*.private-key.pem
gh secret list --repo dmakeienko/adel   # both should be listed
```

Or in the UI: **Repository → Settings → Secrets and variables → Actions →
New repository secret**.

Afterwards, move the `.pem` into your password manager or delete it. You can
always generate a new key; you can't download an existing one again.

## 4. How it's wired

`.github/workflows/release.yml`:

```yaml
release_please:
  env:
    RELEASE_APP_CLIENT_ID: ${{ secrets.RELEASE_APP_CLIENT_ID }}
  steps:
    - name: Generate GitHub App token
      id: app-token
      if: env.RELEASE_APP_CLIENT_ID != ''          # skipped until the secret exists
      uses: actions/create-github-app-token@<sha> # v3.3.0
      with:
        client-id: ${{ secrets.RELEASE_APP_CLIENT_ID }}
        private-key: ${{ secrets.RELEASE_APP_PRIVATE_KEY }}

    - uses: googleapis/release-please-action@<sha> # v5.0.0
      id: release
      with:
        token: ${{ steps.app-token.outputs.token || secrets.GITHUB_TOKEN }}
```

- The token is minted for the current repository only, is valid for 1 hour and
  is revoked automatically at the end of the job.
- `release.yml` is a reusable workflow called from `ci.yml` with
  `secrets: inherit`, so repository secrets are available to it.
- Only release-please uses the App token. GoReleaser, the Docker push and
  chart-releaser keep using `GITHUB_TOKEN`, because they don't need to trigger
  other workflows.
- Because the App creates the tag and GitHub release, a future workflow
  triggered by `on: release` or `on: push: tags` would now actually run. With
  `GITHUB_TOKEN` it would silently not run.

## 5. Repository settings: squash merges only

This fixes the **duplicate entries** in the release notes. With merge commits,
release-please sees both the PR's own commit (`feat: x`) and the merge commit,
whose body repeats the PR title (`Merge pull request #81 …\n\nfeat: x`), so
every change is listed twice.

```bash
gh api -X PATCH repos/dmakeienko/adel \
  -F allow_merge_commit=false \
  -F allow_rebase_merge=false \
  -F allow_squash_merge=true \
  -f squash_merge_commit_title=PR_TITLE \
  -f squash_merge_commit_message=PR_BODY \
  -F delete_branch_on_merge=true
```

UI equivalent: **Settings → General → Pull Requests**. Uncheck *Allow merge
commits* and *Allow rebase merging*, keep *Allow squash merging* with
*Default commit message: Pull request title and description*, and check
*Automatically delete head branches*.

From now on, **the PR title is the changelog entry**, so give PRs
conventional-commit titles (`feat: …`, `fix: …`, `build(deps): …`).
Dependabot already does this.

Recommended: enforce it in the existing `main` ruleset so a merge commit can't
sneak in. Go to **Settings → Rules → Rulesets → main**, check
**Require linear history**, then **Save changes**.

Optional, now that the release PR runs CI: in the same ruleset enable
**Require status checks to pass** and add `Test`, `Lint`,
`Go vulnerability check`, `Validate release archives`. Avoid requiring
`SonarCloud`, which is skipped on Dependabot PRs and would block them.

## 6. Recreate the release PR and verify

The currently open release PR (#76) was created by `github-actions[bot]`.
Let release-please recreate it with the App:

```bash
gh pr close 76 --repo dmakeienko/adel --delete-branch \
  --comment "Recreating with the release GitHub App"
gh pr edit 76 --repo dmakeienko/adel --remove-label "autorelease: pending"
```

The next push to `main` (for example merging this change) runs the
`Release / Release Please` job, which opens a fresh release PR. Check that:

- [ ] In the job log, **Generate GitHub App token** ran (not *skipped*).
- [ ] The new release PR's author is `adel-release-bot[bot]`.
- [ ] The PR's checks start on their own, with no *"workflows awaiting approval"* banner.
- [ ] The PR diff bumps `charts/adel/Chart.yaml` `version` and `appVersion` together with `CHANGELOG.md`.

### One-time cleanup for 1.9.0

Squash merging only affects **new** merges. The merge commits already on `main`
since `v1.8.0` will still produce duplicates in the 1.9.0 notes. Right before
merging the 1.9.0 release PR:

1. Edit the release PR **description** and delete the duplicate bullets.
   release-please builds the GitHub release notes from this description.
2. Edit `CHANGELOG.md` on the `release-please--branches--main` branch the same
   way (GitHub web editor → commit to that branch).
3. Merge right away. Any push to `main` in between makes release-please
   regenerate both, and you'd have to repeat the cleanup.

Releases from 1.10.0 onwards need no manual step.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| *Generate GitHub App token* is **skipped** | `RELEASE_APP_CLIENT_ID` is missing or misspelled, or it was added as a Dependabot/Codespaces secret instead of an Actions secret. |
| `Not Found` / `Integration not found` / `failed to get installation` | The App isn't installed on `adel` (step 2.3), or it was installed on a different account than the repo owner. |
| `A JSON web token could not be decoded` / `error:1E08010C:DECODER routines::unsupported` | The private key secret is truncated or mangled. Re-set it from the file with `gh secret set … < key.pem`. |
| `Resource not accessible by integration` | A permission is missing (most often **Issues: write**, needed for labels). Add it to the App, then accept the new permissions on the installation (see the note in step 2). |
| Release PR still shows *awaiting approval* | The PR was created or last updated with `GITHUB_TOKEN`. Check the token step ran, then recreate the PR (section 6). |
| Release PR is created but the release isn't tagged after merge | The merged PR lost its `autorelease: pending` label. Re-add it and re-run the latest `CI` workflow on `main`. |

## Maintenance

- **Key rotation:** App → *Private keys* → *Generate a private key* → update
  `RELEASE_APP_PRIVATE_KEY` → delete the old key on the same page. An App can
  have several keys at once, so there's no downtime.
- **Revoking access:** uninstall the App or delete its keys. Tokens already
  issued expire within an hour.
- **Action updates:** Dependabot (`github-actions` group) keeps
  `actions/create-github-app-token` pinned and up to date like the other
  actions.
