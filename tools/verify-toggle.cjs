const alias = process.env.TEST_ALIAS || 'j4';
const root = process.env.TEST_ROOT || 'http://160.16.122.233:54321';
async function main() {
  let cookie;
  async function post(path, values) {
    const form = new URLSearchParams();
    for (const [k,v] of Object.entries(values)) form.set(k, typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v));
    const r = await fetch(root + path, {method:'POST', headers:{...(cookie ? {cookie} : {})},body:form,signal:AbortSignal.timeout(15000)});
    if (!cookie) cookie = r.headers.get('set-cookie')?.split(';')[0];
    const d=await r.json(); if (!d.success) throw Error(String(d.msg)); return d.obj;
  }
  await post('/login',{username:process.env.XUI_USERNAME,password:process.env.XUI_PASSWORD});
  const list=await post('/xui/inbound/list',{});
  let port=59998; while(list.some(i=>i.port===port)) port--;
  const value={enable:false,remark:'codex-toggle-test-20261013',port,protocol:'dokodemo-door',settings:JSON.stringify({address:'127.0.0.1',port:9,network:'tcp'}),streamSettings:'{}',sniffing:'{}',total:0,expiryTime:0,listen:''};
  let id;
  async function snap(){const r=await fetch('http://localhost:8787/api/xui/snapshot?fresh=1');return (await r.json()).nodes.find(n=>n.alias===alias.toUpperCase()).ports.find(p=>p.id===id);}
  try {
    await post('/xui/inbound/add',value);
    id=(await post('/xui/inbound/list',{})).find(i=>i.remark===value.remark && i.port===port)?.id;
    if(!id) throw Error('test inbound missing');
    const r=await fetch('http://localhost:8787/api/xui/toggle',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({alias,id,enabled:true})});
    const result=await r.json(); if(!r.ok) throw Error(JSON.stringify(result));
    if(!(await post('/xui/inbound/list',{})).find(i=>i.id===id)?.enable) throw Error('controller to xui failed');
    console.log('CONTROLLER_TO_XUI_OK');
    const inbound=(await post('/xui/inbound/list',{})).find(i=>i.id===id);
    const update={}; for(const field of ['id','up','down','total','remark','expiryTime','listen','port','protocol','settings','streamSettings','sniffing','allocate']) if(inbound[field]!==undefined) update[field]=inbound[field];
    await post('/xui/inbound/update/'+id,{...update,enable:false});
    if((await snap())?.enabled!==false) throw Error('xui to controller failed');
    console.log('XUI_TO_CONTROLLER_REFRESH_OK');
  } finally {if(id){await post('/xui/inbound/del/'+id,{});console.log('TEST_INBOUND_REMOVED');}}
}
main().catch(e=>{console.error(e.message);process.exitCode=1});
