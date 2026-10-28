// No network APIs: plaintext is encrypted in browser memory, never sent.
const b64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unpem=pem=>Uint8Array.from(atob(pem.replace(/-----[^-]+-----/g,'').replace(/\s/g,'')),c=>c.charCodeAt(0));
export async function encryptKey(apiKey,config,crypto=globalThis.crypto){
 if(typeof apiKey!=='string'||!apiKey||apiKey.length>4096||/[\s\x00-\x1f\x7f]/.test(apiKey))throw new Error('Invalid API key');
 const recipient=await crypto.subtle.importKey('spki',unpem(config.publicKeyPem),{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
 const aes=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt']);
 const iv=crypto.getRandomValues(new Uint8Array(12));
 const payload=new TextEncoder().encode(JSON.stringify({purpose:'gmgn-api-key-transfer-v1',request_id:config.requestId,api_key:apiKey}));
 const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode(config.requestId)},aes,payload);
 const encrypted=await crypto.subtle.encrypt({name:'RSA-OAEP'},recipient,await crypto.subtle.exportKey('raw',aes));
 return {version:1,algorithm:'RSA-OAEP-256+A256GCM',request_id:config.requestId,encrypted_key:b64(encrypted),iv:b64(iv),ciphertext:b64(ciphertext)};
}
