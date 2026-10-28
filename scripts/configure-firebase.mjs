import {readFile,writeFile,rename} from 'node:fs/promises';
import {resolve} from 'node:path';
// Input is the CLI SDK config JSON, not an Admin service-account file.
let raw='';for await(const chunk of process.stdin){raw+=chunk;if(raw.length>100000)throw Error('Input is too large');}
const parsed=JSON.parse(raw),data=parsed.result?.sdkConfig||parsed.sdkConfig||parsed.result||parsed;
const config=typeof data==='string'?JSON.parse(data):data;
if(config.private_key||config.client_email)throw Error('Admin credentials must never be published');
const out={};for(const key of ['apiKey','authDomain','projectId','appId']){if(typeof config[key]!=='string'||!config[key]||config[key].length>300)throw Error('Missing public SDK field: '+key);out[key]=config[key];}
if(!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(out.projectId)||out.authDomain!==out.projectId+'.firebaseapp.com')throw Error('Unexpected project identifiers');
const root=resolve(import.meta.dirname,'..'),target=resolve(root,'dist/diary/firebase-config.mjs'),temp=target+'.tmp';
await writeFile(temp,'// Public Firebase Web app identifiers. Authorization is enforced by deployed rules.\nexport const firebaseConfig = '+JSON.stringify(out,null,2)+';\n');
await rename(temp,target);
console.log('Public Firebase Web identifiers configured; no credential material printed');
