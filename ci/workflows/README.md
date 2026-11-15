# Ghost-Tag CI/CD Workflows

This directory contains the production GitHub Actions workflows and autonomous agent pipelines for Ghost-Tag:

1. **`ci.yml`**: TypeCheck (`tsc --noEmit`), Jest unit & integration test suite (130 tests), test coverage report.
2. **`agent-security-audit.yml`**: Autonomous Security Auditor Agent executing zero-secrets audits, Android hardware defense validation, and invariant checks.
3. **`agent-quality-gate.yml`**: Autonomous Quality Assurance Agent enforcing strict type checking, version synchronization, and test suite pass rates.
4. **`android-build.yml`**: Release APK compilation, Android SDK build, and SHA-256 checksum generation.
5. **`deploy-pages.yml`**: Automated GitHub Pages deployment for the web showcase in `web/`.
6. **`release.yml`**: Automated tag release builder (`v*`) with APK artifact attachment.

---

## Activating Workflows in GitHub Actions

GitHub's OAuth security policy requires the `workflow` token scope to create or modify files inside the protected `.github/workflows/` directory.

To enable GitHub Actions in your repository:
1. Run in your terminal:
   ```bash
   gh auth refresh -s workflow
   ```
2. Copy these workflow files into `.github/workflows/`:
   ```bash
   mkdir -p .github/workflows
   cp ci/workflows/*.yml .github/workflows/
   git add .github/workflows/
   git commit -m "ci: activate GitHub Actions workflows"
   git push origin main
   ```
   Or copy their contents directly via the GitHub Web UI under **Actions** -> **New workflow**.
