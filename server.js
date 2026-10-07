const express=require('express'),Db=require('better-sqlite3'),bc=require('bcryptjs'),jwt=require('jsonwebtoken'),cp=require('cookie-parser'),crypto=require('crypto');
const SECRET=process.env.JWT_SECRET;if(!SECRET||SECRET.length<24){console.error('Set JWT_SECRET (24+ chars)');process.exit(1)}
const db=new Db(process.env.DB_FILE||'psp.db');db.pragma('journal_mode=WAL');
db.exec("create table if not exists users(id text primary key,name text,role text,user text unique,pw text);create table if not exists docs(kind text,id text,j text,primary key(kind,id))");
const uid=()=>crypto.randomBytes(5).toString('hex'),now=()=>new Date().toISOString();
const get=(k,id)=>{const r=db.prepare('select j from docs where kind=? and id=?').get(k,String(id));return r&&JSON.parse(r.j)};
const all=k=>db.prepare('select j from docs where kind=?').all(k).map(r=>JSON.parse(r.j));
const put=(k,o)=>db.prepare('insert or replace into docs values(?,?,?)').run(k,o.id,JSON.stringify(o));
const del=(k,id)=>db.prepare('delete from docs where kind=? and id=?').run(k,String(id));
const aud=(u,a,o,p,n)=>put('audit',{id:Date.now()+'-'+uid(),t:now(),u:u?u.name:'-',a,o:o||'',p:p||'',n:n||''});
if(!db.prepare('select 1 from users').get()){const pw=process.env.ADMIN_PASSWORD||crypto.randomBytes(9).toString('base64url');db.prepare('insert into users values(?,?,?,?,?)').run(uid(),'Administrator','Admin','admin',bc.hashSync(pw,12));console.log('Created user admin / password:',pw,'(change/store it now)')}
const ST=['Active','Inactive','Transferred','Resigned'],FQ=['Daily','Weekly','Monthly','Custom'];
function score(r){const t=get('templates',r.tpl),v=t&&t.versions.find(x=>x.v==r.v);if(!v)return 0;let y=0,n=0;v.sections.forEach(s=>s.qs.forEach(q=>{if(q.type!='yn')return;const a=(r.ans[q.id]||{}).a;if(a=='Yes')y++;else if(a=='No')n++}));return y+n?Math.round(y/(y+n)*100):0}
const app=express();app.disable('x-powered-by');app.set('trust proxy',1);app.use(express.json({limit:'2mb'}),cp());
app.use((q,s,n)=>{s.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:"});n()});
const fails={};
app.post('/api/login',(q,s)=>{const ip=q.ip,f=fails[ip]||(fails[ip]={n:0,t:Date.now()});if(Date.now()-f.t>9e5){f.n=0;f.t=Date.now()}if(f.n>=10)return s.sendStatus(429);const{user,pw}=q.body||{},u=db.prepare('select * from users where user=?').get(String(user||'').toLowerCase());if(!u||!bc.compareSync(String(pw||''),u.pw)){f.n++;aud(null,'Failed login',String(user||'').slice(0,40));return s.sendStatus(401)}
s.cookie('tk',jwt.sign({id:u.id},SECRET,{expiresIn:'8h'}),{httpOnly:true,sameSite:'strict',secure:process.env.COOKIE_SECURE==='1',maxAge:288e5});aud(u,'Login','User');s.json({ok:1})});
app.post('/api/logout',(q,s)=>{s.clearCookie('tk');s.json({ok:1})});
const auth=(q,s,n)=>{try{const p=jwt.verify(q.cookies.tk,SECRET);q.u=db.prepare('select * from users where id=?').get(p.id);if(!q.u)throw 0;n()}catch(x){s.sendStatus(401)}};
function state(u){const sp=u.role=='Supervisor';return{me:{id:u.id,name:u.name,role:u.role},db:{users:db.prepare('select id,name,role,user from users').all(),agents:all('agents').filter(a=>!sp||a.sup==u.id),templates:all('templates'),records:all('records').filter(r=>!sp||r.sup==u.id),audit:sp?[]:all('audit').sort((a,b)=>b.t.localeCompare(a.t)).slice(0,300)}}}
app.get('/api/state',auth,(q,s)=>s.json(state(q.u)));
app.post('/api/users',auth,(q,s)=>{if(q.u.role!='Admin')return s.sendStatus(403);const{name,user,role,pw}=q.body||{};if(!name||!/^[a-z0-9._-]{3,30}$/i.test(user||'')||!['Admin','Supervisor','QA'].includes(role)||String(pw||'').length<10)return s.status(400).json({error:'Invalid input (password min 10 chars)'});try{db.prepare('insert into users values(?,?,?,?,?)').run(uid(),String(name).slice(0,100),role,user.toLowerCase(),bc.hashSync(pw,12))}catch(x){return s.status(409).json({error:'Username exists'})}aud(q.u,'User created',user,'',role);s.json({ok:1})});
app.put('/api/state',auth,(q,s)=>{const u=q.u,b=q.body||{},sp=u.role=='Supervisor',map={};
db.transaction(()=>{
if(u.role!='QA')for(const a of b.agents||[]){if(!a||!a.id||typeof a.name!='string'||!a.name.trim()||!ST.includes(a.status)||!FQ.includes(a.freq))continue;const o=get('agents',a.id);if(sp&&(a.sup!=u.id||(o&&o.sup!=u.id)))continue;if(!db.prepare('select 1 from users where id=? and role=?').get(a.sup,'Supervisor'))continue;
const c={id:String(a.id).slice(0,40),name:a.name.slice(0,120),code:String(a.code||'').slice(0,40),program:String(a.program||'').slice(0,80),sup:a.sup,start:String(a.start||'').slice(0,10),status:a.status,freq:a.freq,per:+a.per||4};if(!o||JSON.stringify(o)!=JSON.stringify(c)){put('agents',c);aud(u,o?'Agent updated':'Agent created',c.name,o?[o.status,o.freq,o.sup].join('/'):'',[c.status,c.freq,c.sup].join('/'))}}
if(u.role!='QA')for(const t of b.templates||[]){if(!t||!t.id||!t.name)continue;const n=get('templates',t.id)||{id:String(t.id).slice(0,40),name:String(t.name).slice(0,150),program:String(t.program||'').slice(0,80),versions:[]};
for(const v of t.versions||[]){const ov=n.versions.find(x=>x.v==v.v);if(!ov){n.versions.push({v:String(v.v),date:v.date,sections:v.sections,status:u.role=='Admin'&&v.status=='Approved'?'Approved':'Pending approval'});aud(u,'Template uploaded',n.name,'',v.v)}else if(u.role=='Admin'&&ov.status!='Approved'&&v.status=='Approved'){ov.status='Approved';aud(u,'Template approved',n.name,'',v.v)}}
if(n.versions.length)put('templates',n)}
for(const r of b.records||[]){if(!r||!r.id)continue;const o=get('records',r.id);
if(o&&o.status=='Submitted'){let ch=0;if(['QA','Admin'].includes(u.role)||o.sup==u.id){if(r.fx&&JSON.stringify(r.fx)!=JSON.stringify(o.fx||{})){o.fx=r.fx;ch=1;aud(u,'Finding updated',o.id)}}
if(u.role=='QA'&&r.qa&&!o.qa){o.qa={name:u.name,at:now()};ch=1;aud(u,'QA signed',o.id)}
if((u.role=='Admin'||o.sup==u.id)&&(r.hist||[]).length==(o.hist||[]).length+1&&r.ans){const h=r.hist[r.hist.length-1],p=o.score;o.hist=(o.hist||[]).concat({t:now(),u:u.name,reason:String(h.reason||'').slice(0,500),prev:p,ansPrev:JSON.stringify(o.ans)});o.ans=r.ans;o.sig=String(r.sig||o.sig).slice(0,100);o.score=score(o);ch=1;aud(u,'Monitoring corrected',o.id,p+'%',o.score+'%')}
if(ch)put('records',o);continue}
if(!sp||r.sup!=u.id||!['Draft','Submitted'].includes(r.status))continue;
const ag=get('agents',r.agent),t=get('templates',r.tpl),v=t&&t.versions.find(x=>x.v==r.v);if(!ag||ag.sup!=u.id||!v||v.status!='Approved'||(o&&o.sup!=u.id))continue;
const c={id:r.id,agent:r.agent,tpl:r.tpl,v:r.v,date:String(r.date).slice(0,10),sup:u.id,status:r.status,ans:r.ans||{},sig:String(r.sig||'').slice(0,100)};
if(r.status=='Draft'){if(/^DRAFT-[a-z0-9]+$/.test(c.id)){c.score=0;put('records',c);aud(u,'Draft saved',c.id)}continue}
if(!c.sig)continue;const n=db.prepare("select count(*) c from docs where kind='records' and json_extract(j,'$.status')='Submitted'").get().c+245;c.id='MON-'+new Date().getFullYear()+'-'+String(n).padStart(6,'0');c.score=score(c);c.signedAt=now();put('records',c);map[r.id]=c.id;
if(r._old){const d=get('records',r._old);if(d&&d.status=='Draft'&&d.sup==u.id)del('records',r._old)}aud(u,'Monitoring submitted',c.id,'',c.score+'%')}
})();const st=state(u);st.map=map;s.json(st)});
app.get('/',(q,r)=>r.sendFile(__dirname+'/index.html'));
app.listen(process.env.PORT||3000,()=>console.log('PSP server on',process.env.PORT||3000));
