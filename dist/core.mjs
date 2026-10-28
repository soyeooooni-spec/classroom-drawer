const integer=(v,min,max)=>{if(!Number.isInteger(v)||v<min||v>max)throw Error('입력 범위를 확인해 주세요.');return v;};
export function safeUrl(value){
 if(typeof value!=='string'||value.length>2048||/[\u0000-\u0020\u007f]/.test(value))throw Error('주소를 확인해 주세요.');
 const u=new URL(value);
 if(u.username||u.password||u.hash||[...u.searchParams.keys()].some(k=>/token|secret|password|key|auth|code|email/i.test(k)))throw Error('인증정보가 없는 일반 주소를 넣어 주세요.');
 if(u.href==='http://127.0.0.1:8765/')return u.href;
 if(u.protocol!=='https:'||u.port||!u.hostname.includes('.')||/^localhost$|\.localhost$|\.local$|\.internal$|\.localhost\.$|\.local\.$|\.internal\.$|^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.|^169\.254\.|^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|^0\.|^\[/.test(u.hostname))throw Error('공개 HTTPS 주소를 넣어 주세요.');
 return u.href;
}
function random(n){const a=new Uint32Array(1),limit=4294967296-(4294967296%n);do{crypto.getRandomValues(a);}while(a[0]>=limit);return a[0]%n;}
export function makeGroups(n,g){integer(n,2,60);integer(g,2,Math.min(n,12));const a=Array.from({length:n},(_,i)=>i+1);for(let i=n-1;i>0;i--){const j=random(i+1);[a[i],a[j]]=[a[j],a[i]];}const groups=Array.from({length:g},()=>[]);a.forEach((v,i)=>groups[i%g].push(v));return groups;}
export function drawNumber(n,excluded=[]){integer(n,1,60);const a=Array.from({length:n},(_,i)=>i+1).filter(v=>!excluded.includes(v));return a.length?a[random(a.length)]:null;}
const enc=new TextEncoder(),dec=new TextDecoder();
const b64=a=>{let s='';for(let i=0;i<a.length;i+=8192)s+=String.fromCharCode(...a.subarray(i,i+8192));return btoa(s);};
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function key(password,salt){if(typeof password!=='string'||password.length<10||password.length>200)throw Error('비밀번호는 10~200자로 입력해 주세요.');const raw=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:310000,hash:'SHA-256'},raw,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
export function validateApps(data){if(!Array.isArray(data)||data.length>100)throw Error('앱은 100개까지 등록할 수 있어요.');const ids=new Set(['diary','diary-local','timer','picker','groups','traffic','questions']);return data.map(x=>{if(!x||typeof x.id!=='string'||!/^[a-zA-Z0-9-]{1,50}$/.test(x.id)||ids.has(x.id)||typeof x.name!=='string'||!x.name.trim()||x.name.length>50)throw Error('앱 형식을 확인해 주세요.');ids.add(x.id);return {id:x.id,name:x.name.trim(),url:safeUrl(x.url)};});}
export async function encryptVault(data,password){data=validateApps(data);const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},await key(password,salt),enc.encode(JSON.stringify(data)));return {v:1,iterations:310000,salt:b64(salt),iv:b64(iv),cipher:b64(new Uint8Array(cipher))};}
export async function decryptVault(data,password){if(!data||data.v!==1||data.iterations!==310000||typeof data.cipher!=='string'||data.cipher.length>400000||typeof data.salt!=='string'||data.salt.length!==24||typeof data.iv!=='string'||data.iv.length!==16)throw Error('백업 형식이 올바르지 않습니다.');const salt=unb64(data.salt),iv=unb64(data.iv);if(salt.length!==16||iv.length!==12)throw Error('백업 형식이 올바르지 않습니다.');const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv},await key(password,salt),unb64(data.cipher));return validateApps(JSON.parse(dec.decode(plain)));}
