import {readdir,readFile} from 'node:fs/promises';
import {resolve,relative} from 'node:path';
const root=resolve(import.meta.dirname,'..');
const selected=['dist','tests','scripts','.github','README.md','SECURITY.md','package.json','.gitignore','AUDIT.md','firebase.json','firestore.rules','firestore.indexes.json'];
const forbidden=[/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,/\bgh[pousr]_[A-Za-z0-9]{20,}/,/\bya29\.[A-Za-z0-9_-]{20,}/,/"private_key"\s*:/,/C:[\\/]Users[\\/]/i];
let count=0;
async function walk(path){let children;try{children=await readdir(path,{withFileTypes:true});}catch{const text=await readFile(path,'utf8');for(const pattern of forbidden)if(pattern.test(text))throw Error('Sensitive material pattern in '+relative(root,path));count++;return;}for(const child of children){if(child.name==='node_modules')throw Error('Unexpected dependency directory in publication');await walk(resolve(path,child.name));}}
for(const path of selected)await walk(resolve(root,path));
console.log('Publication scan PASS: '+count+' selected text files; no matching private-key/token/local-path patterns');
