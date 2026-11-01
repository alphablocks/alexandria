"""Create a build-only, history-free source snapshot for an authorized remote.

Do not copy the workspace, Git history, credentials, memories or build caches.
The generated workspace does not inherit the web template's overrides removing
Windows Rollup binaries. Catalog references are resolved to explicit versions.
"""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
DEST = Path(sys.argv[1]).resolve()
assert DEST.is_relative_to(ROOT / "generated-artifacts"), "Use ignored output storage"
DEST.mkdir(parents=True, exist_ok=True)
names = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard",
     "desktop/alexandria-vault"], cwd=ROOT, text=True
).splitlines()
files = sorted(set(names) | {
    "LICENSE", ".github/workflows/windows-vault.yml",
    "research/horizontal-memory/example-context-pack.json",
})
allowed = {".rs", ".toml", ".lock", ".json", ".ts", ".tsx", ".css",
           ".html", ".md", ".swift", ".sh", ".ps1", ".py", ".png", ".ico"}
for name in files:
    source = ROOT / name
    if name.startswith("desktop/"):
        assert source.suffix in allowed, f"Unexpected source type: {name}"
        assert not any(part in {"node_modules", "target", "ui-dist", "binaries", "gen"}
                       for part in source.parts), name
    assert not source.is_symlink() and source.is_file(), name
    target = DEST / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)

package_path = DEST / "desktop/alexandria-vault/package.json"
package = json.loads(package_path.read_text())
catalog_text = (ROOT / "pnpm-workspace.yaml").read_text().split("catalog:", 1)[1]
for section in ("dependencies", "devDependencies"):
    for key, value in package.get(section, {}).items():
        if value == "catalog:":
            match = re.search(r"^  ['\"]?" + re.escape(key) +
                              r"['\"]?:\s*['\"]?([^'\"\n]+)", catalog_text, re.M)
            assert match, f"Missing catalog dependency: {key}"
            package[section][key] = match[1].strip()
package_path.write_text(json.dumps(package, indent=2) + "\n")
(DEST / "package.json").write_text(json.dumps({
    "name": "alexandria-build", "private": True, "license": "MIT",
    "packageManager": "pnpm@10.26.1",
}, indent=2) + "\n")
(DEST / "pnpm-workspace.yaml").write_text("packages:\n  - desktop/*\n")
(DEST / ".gitignore").write_text(
    "node_modules/\n**/target/\n**/ui-dist/\n**/native/gen/\n"
    "**/native/binaries/\ngenerated-artifacts/\n*.mcpb\n.env*\n*.db*\n*.dpapi\n"
)
(DEST / "README.md").write_text(
    "# Alexandria local memory vault\n\n"
    "MIT-licensed, build-only source snapshot. Windows 11 x64 / Windows Hello.\n\n"
    "See [the desktop guide](desktop/alexandria-vault/README.md) and "
    "[actual verification boundaries](desktop/alexandria-vault/VERIFICATION.md).\n\n"
    "This repository excludes the dataset website, workspace history, personal "
    "memories, credentials and unrelated attachments. The synthetic context pack "
    "is a test fixture. Desktop package catalog references are resolved to "
    "explicit dependency versions; the build workspace has its own frozen lock.\n\n"
    "Actions produces UNSIGNED experimental artifacts, not a signed public release. "
    "Unattended CI cannot verify Windows Hello, session/suspend behavior, native "
    "dialogs, recovery or live Claude use. Do not bypass OS or organization policy.\n"
)
print(f"Staged {len(files)} allowlisted source files. No Git history was copied.")
