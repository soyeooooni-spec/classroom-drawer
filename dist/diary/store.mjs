import {validateEnvelope} from './crypto.mjs';
const failure=code=>Object.assign(Error(code),{code});
export function validateRecord(data){if(!data||Object.keys(data).length!==2||!Object.hasOwn(data,'version')||!Object.hasOwn(data,'envelope')||!Number.isInteger(data.version)||data.version<1||data.version>1000000000)throw failure('invalid-record');validateEnvelope(data.envelope);return {version:data.version,envelope:data.envelope};}
export function createJournalStore(transport){
 const check=uid=>{if(typeof uid!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(uid)||transport.uid()!==uid)throw failure('auth/session-changed');};
 return {
  async read(uid){check(uid);const data=await transport.get(uid);check(uid);return data===null?null:validateRecord(data);},
  async write(uid,envelope,expected){check(uid);validateEnvelope(envelope);if(!Number.isInteger(expected)||expected<0||expected>=1000000000)throw failure('invalid-version');return transport.transaction(async transaction=>{check(uid);const current=await transaction.read(uid);check(uid);const version=current===null?0:validateRecord(current).version;if(version!==expected)throw failure('conflict');const next={version:expected+1,envelope};transaction.write(next,uid);return next.version;});}
 };
}
