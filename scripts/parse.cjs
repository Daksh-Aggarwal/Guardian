// Trusted syntax front end. Untrusted source is never evaluated or imported.
const { analyzeProject } = require("./static-flow.cjs");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
});
process.stdin.on("end", () => {
  const payload = JSON.parse(input);
  process.stdout.write(
    JSON.stringify(
      analyzeProject(payload.files || payload, payload.limits || {}),
    ),
  );
});
