# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report privately through GitHub: **Security** tab, then **Report a vulnerability**,
or email **skhirirayen@outlook.com** with "SECURITY: detection-library" in the subject.

Include what you found, how to reproduce it, and the impact you expect.
I reply within 3 working days and will credit you in the fix unless you prefer otherwise.

## Scope

The rule compiler, the browser engine, the GitHub Actions workflows and the playground at detections.rayenskhiri.online. A detection that can be trivially bypassed is welcome as a normal issue or pull request, since it is a quality problem rather than a vulnerability.

## How this repository is protected

- Secret scanning (gitleaks) and CodeQL run on every push and pull request.
- Dependencies are audited in CI and kept current by Dependabot.
- No credentials are stored in the repository. Secrets live in GitHub Actions secrets or in local, git-ignored files.
