import {encryptKey} from './encrypt.mjs';
import {config} from './config.mjs';
const input=document.getElementById('key'),button=document.getElementById('encrypt'),status=document.getElementById('status'),result=document.getElementById('result'),download=document.getElementById('download'),cipher=document.getElementById('ciphertext');
let blobUrl=null;
document.getElementById('fingerprint').textContent=config.fingerprint.slice(0,16);
const supported=globalThis.isSecureContext&&globalThis.crypto?.subtle;
const expired=Date.now()/1000>config.expiresAt;
button.disabled=!supported||expired;
status.textContent=!supported?'Этот браузер не поддерживает защищённое шифрование. Открой ссылку в обычном Safari или Chrome.':expired?'Запрос истёк. Попроси новую ссылку; не отправляй ключ в чат.':'Готово. Ключ останется на устройстве до шифрования.';
document.getElementById('form').addEventListener('submit',async event=>{
 event.preventDefault();if(button.disabled)return;button.disabled=true;result.hidden=true;
 try{
  if(Date.now()/1000>config.expiresAt)throw new Error('Expired request');
  const envelope=await encryptKey(input.value,config);
  input.value='';
  const text=JSON.stringify(envelope,null,2);
  if(blobUrl)URL.revokeObjectURL(blobUrl);
  blobUrl=URL.createObjectURL(new Blob([text],{type:'application/json'}));
  download.href=blobUrl;download.download='gmgn-key-'+config.requestId.slice(0,8)+'.gmgn.enc.json';
  cipher.value=text;result.hidden=false;
  status.textContent='Зашифровано. Поле ключа очищено. Скачай файл ниже и отправь его в чат.';
 }catch{
  input.value='';status.textContent='Не получилось зашифровать. Проверь, что ключ без пробелов, и что ссылка не истекла. Ключ никуда не отправлен.';
 }finally{button.disabled=Date.now()/1000>config.expiresAt;}
});
document.getElementById('copy').addEventListener('click',async()=>{
 try{await navigator.clipboard.writeText(cipher.value);status.textContent='Шифротекст скопирован. Его можно отправить в чат.';}
 catch{cipher.focus();cipher.select();status.textContent='Выделен только шифротекст. Скопируй его вручную.';}
});
