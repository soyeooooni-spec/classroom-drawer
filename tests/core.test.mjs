import test from 'node:test';
import assert from 'node:assert/strict';
import {safeUrl, makeGroups, drawNumber, encryptVault, decryptVault} from '../dist/core.mjs';
test('links allow HTTPS and the exact diary only',()=>{
 assert.equal(safeUrl('https://example.org/app'),'https://example.org/app');
 for(const u of ['javascript:alert(1)','data:text/html,x','http://example.org','https://user:pass@example.org','https://127.0.0.1','https://localhost','https://example.org/?token=secret']) assert.throws(()=>safeUrl(u));
 assert.equal(safeUrl('http://127.0.0.1:8765/'),'http://127.0.0.1:8765/');
});
test('groups cover each number once and remain balanced',()=>{
 for(let n=2;n<=60;n++) for(let g=2;g<=Math.min(n,12);g++){
  const a=makeGroups(n,g); assert.equal(a.length,g);
  assert.deepEqual(a.flat().sort((a,b)=>a-b),Array.from({length:n},(_,i)=>i+1));
  assert.ok(Math.max(...a.map(x=>x.length))-Math.min(...a.map(x=>x.length))<=1);
 }
 assert.throws(()=>makeGroups(0,2)); assert.throws(()=>makeGroups(5,6));
});
test('drawing excludes selected numbers and detects empty pool',()=>{
 assert.equal(drawNumber(3,[1,3]),2); assert.equal(drawNumber(2,[1,2]),null);
 assert.throws(()=>drawNumber(61,[]));
});
test('vault encrypts and authenticates metadata',async()=>{
 const data=[{id:'test',name:'가상 도구',url:'https://example.org/'}];
 const encrypted=await encryptVault(data,'test-only-long-passphrase');
 assert.ok(!JSON.stringify(encrypted).includes('example.org'));
 assert.deepEqual(await decryptVault(encrypted,'test-only-long-passphrase'),data);
 await assert.rejects(()=>decryptVault(encrypted,'wrong-password'));
 await assert.rejects(()=>decryptVault({...encrypted,iterations:1},'test-only-long-passphrase'));
});
test('vault supports 100 long links',async()=>{
 const data=Array.from({length:100},(_,i)=>({id:'app-'+i,name:'가상 도구',url:'https://example.org/'+('a'.repeat(1900))}));
 const encrypted=await encryptVault(data,'test-only-long-passphrase');
 assert.deepEqual(await decryptVault(encrypted,'test-only-long-passphrase'),data);
});
