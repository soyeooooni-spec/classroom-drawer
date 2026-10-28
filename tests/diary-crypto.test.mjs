import test from 'node:test';
import assert from 'node:assert/strict';
import {sealJournal,openJournal,validateEntries,validateEnvelope} from '../dist/diary/crypto.mjs';
const uid='synthetic-test-user';
const sample=[{id:'11111111-1111-4111-8111-111111111111',date:'2026-10-28',title:'가상 제목',body:'실제 개인정보가 없는 가상 기록',mood:'calm'}];
test('journal encrypts all content and is bound to the signed-in UID',async()=>{
 const envelope=await sealJournal(sample,'synthetic-only-long-passphrase',uid);
 assert.ok(!JSON.stringify(envelope).includes('2026-10-28'));
 assert.ok(!JSON.stringify(envelope).includes('가상'));
 assert.deepEqual(await openJournal(envelope,'synthetic-only-long-passphrase',uid),sample);
 await assert.rejects(()=>openJournal(envelope,'wrong-test-passphrase',uid));
 await assert.rejects(()=>openJournal(envelope,'synthetic-only-long-passphrase','another-test-user'));
 const altered={...envelope,iv:envelope.iv.replace(/^./,envelope.iv[0]==='A'?'B':'A')};
 await assert.rejects(()=>openJournal(altered,'synthetic-only-long-passphrase',uid));
});
test('journal rejects invalid dates, duplicate dates, unknown fields and excessive content',()=>{
 assert.throws(()=>validateEntries([{...sample[0],date:'2026-02-30'}]));
 assert.throws(()=>validateEntries([sample[0],{...sample[0],id:'22222222-2222-4222-8222-222222222222'}]));
 assert.throws(()=>validateEntries([{...sample[0],email:'synthetic@example.invalid'}]));
 assert.throws(()=>validateEntries([{...sample[0],body:'x'.repeat(100001)}]));
 assert.throws(()=>validateEntries([{...sample[0],mood:'unknown'}]));
});
test('envelopes reject costly/oversized/extra payloads before derivation',()=>{
 assert.throws(()=>validateEnvelope({schema:1,iterations:1,salt:'A'.repeat(24),iv:'A'.repeat(16),cipher:'A'.repeat(50)}));
 assert.throws(()=>validateEnvelope({schema:1,iterations:600000,salt:'A'.repeat(24),iv:'A'.repeat(16),cipher:'A'.repeat(700001)}));
});
test('same entry encrypts differently on every save',async()=>{
 const a=await sealJournal(sample,'synthetic-only-long-passphrase',uid);
 const b=await sealJournal(sample,'synthetic-only-long-passphrase',uid);
 assert.notEqual(a.iv,b.iv);assert.notEqual(a.salt,b.salt);assert.notEqual(a.cipher,b.cipher);
});
