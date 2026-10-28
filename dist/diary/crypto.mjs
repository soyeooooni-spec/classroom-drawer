const encoder=new TextEncoder(),decoder=new TextDecoder('utf-8',{fatal:true});
const MOODS=new Set(['happy','calm','ordinary','sad','tired']);
const exact=(x,keys)=>x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
function validDate(s){if(typeof s!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(s)||s<'1900-01-01'||s>'2199-12-31')return false;const d=new Date(s+'T00:00:00Z');return !isNaN(d)&&d.toISOString().slice(0,10)===s;}
export function validateEntries(entries){
 if(!Array.isArray(entries)||entries.length>500)throw Error('일기는 최대 500편까지 보관할 수 있어요.');
 const dates=new Set(),ids=new Set();
 const result=entries.map(e=>{if(!exact(e,['id','date','title','body','mood'])||typeof e.id!=='string'||!/^[a-f0-9-]{36}$/.test(e.id)||ids.has(e.id)||!validDate(e.date)||dates.has(e.date)||typeof e.title!=='string'||e.title.length>120||typeof e.body!=='string'||!e.body.trim()||e.body.length>100000||!MOODS.has(e.mood))throw Error('일기 형식·날짜·중복·글자 수를 확인해 주세요.');dates.add(e.date);ids.add(e.id);return {id:e.id,date:e.date,title:e.title,body:e.body,mood:e.mood};});
 if(encoder.encode(JSON.stringify(result)).length>500000)throw Error('전체 기록이 저장 한도에 도달했어요. 암호화 백업을 보관하고 기록을 정리해 주세요.');
 return result;
}
function b64(bytes){let s='';for(let i=0;i<bytes.length;i+=8192)s+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(s);}
function unb64(s){if(typeof s!=='string'||s.length%4||! /^[A-Za-z0-9+/]*={0,2}$/.test(s))throw Error('암호화 형식 오류');return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
export function validateEnvelope(e){if(!exact(e,['schema','iterations','salt','iv','cipher'])||e.schema!==1||e.iterations!==600000||typeof e.salt!=='string'||e.salt.length!==24||typeof e.iv!=='string'||e.iv.length!==16||typeof e.cipher!=='string'||e.cipher.length<24||e.cipher.length>700000||unb64(e.salt).length!==16||unb64(e.iv).length!==12)throw Error('암호화 기록 형식을 확인해 주세요.');unb64(e.cipher);return e;}
async function derive(password,salt){if(typeof password!=='string'||password.length<12||password.length>200)throw Error('일기 암호는 12~200자로 입력해 주세요.');const material=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',iterations:600000,salt},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
function aad(uid){if(typeof uid!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(uid))throw Error('로그인 상태를 확인해 주세요.');return encoder.encode('haru-journal-v1:'+uid);}
export async function sealJournal(entries,password,uid){const plain=encoder.encode(JSON.stringify(validateEntries(entries)));const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(uid)},await derive(password,salt),plain);plain.fill(0);return {schema:1,iterations:600000,salt:b64(salt),iv:b64(iv),cipher:b64(new Uint8Array(cipher))};}
export async function openJournal(envelope,password,uid){const e=validateEnvelope(envelope);const bytes=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(e.iv),additionalData:aad(uid)},await derive(password,unb64(e.salt)),unb64(e.cipher)));try{return validateEntries(JSON.parse(decoder.decode(bytes)));}finally{bytes.fill(0);}}
