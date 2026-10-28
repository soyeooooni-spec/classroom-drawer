import test from 'node:test';
import assert from 'node:assert/strict';
import {safeUrl,validateApps} from '../dist/core.mjs';
test('URL controls, metadata endpoints, encoded credentials are rejected',()=>{
 for(const u of ['https://example.org/?api_key=x','https://example.org/?access_token=x','https://example.org/#private','https://metadata.google.internal/','https://100.64.0.1/','https://2130706433/','https://example.org/\nprivate'])assert.throws(()=>safeUrl(u),u);
});
test('built-in IDs cannot be impersonated by imported apps',()=>{
 assert.throws(()=>validateApps([{id:'diary',name:'가상 앱',url:'https://example.org/'}]));
});
