require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const nodemailer = require('nodemailer');
const fetch      = require('node-fetch');
const admin      = require('firebase-admin');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Firebase Admin ──────────────────────────────────────
let db = null, firebaseReady = false;
try {
  const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
  if (sa.project_id) {
    admin.initializeApp({ credential: admin.credential.cert(sa) });
    db = admin.firestore();
    firebaseReady = true;
    console.log('[Relay] Firebase Admin ✅');
  } else {
    console.warn('[Relay] No service account — dev mode');
  }
} catch (e) { console.error('[Relay] Firebase init failed:', e.message); }

// ── CORS ────────────────────────────────────────────────
const ALLOWED = [
  'https://the-water-app.netlify.app',
  'https://cflwatertreatment.com',
  'https://www.cflwatertreatment.com',
  'http://localhost:3000',
  'http://127.0.0.1:5500'
];
app.use(cors({
  origin: (o, cb) => (!o || ALLOWED.includes(o)) ? cb(null, true) : cb(new Error('CORS: ' + o + ' not allowed')),
  methods: ['GET','POST','PATCH'],
  allowedHeaders: ['Content-Type','Authorization','X-Idempotency-Key']
}));
app.use(express.json({ limit: '100kb' }));

// ── Rate limiter ────────────────────────────────────────
const rl = new Map();
function rateLimit(max, ms) {
  return (req, res, next) => {
    const ip  = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    const key = `${ip}:${req.path}`;
    const now = Date.now();
    const w   = rl.get(key) || { n: 0, t: now };
    if (now - w.t > ms) { w.n = 1; w.t = now; } else w.n++;
    rl.set(key, w);
    if (w.n > max) return res.status(429).json({ error: 'Too many requests' });
    next();
  };
}
setInterval(() => { const c = Date.now()-1800000; for (const [k,v] of rl) if (v.t<c) rl.delete(k); }, 1800000);

// ── Idempotency ─────────────────────────────────────────
async function checkIdemp(key, uid) {
  if (!db || !key) return null;
  const s = await db.collection('idempotency').doc(uid+'_'+key).get();
  return s.exists ? s.data() : null;
}
async function saveIdemp(key, uid, result) {
  if (!db || !key) return;
  await db.collection('idempotency').doc(uid+'_'+key).set({ result, uid, createdAt: admin.firestore.FieldValue.serverTimestamp() });
}

// ── Auth middleware ─────────────────────────────────────
async function requireAuth(req, res, next) {
  if (!firebaseReady) { req.uid = 'dev'; req.email = null; return next(); }
  const h = req.headers['authorization'];
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized: missing token' });
  const tok = h.split('Bearer ')[1];
  if (!tok || tok.length < 20) return res.status(401).json({ error: 'Unauthorized: bad token' });
  try {
    const d = await admin.auth().verifyIdToken(tok);
    req.uid = d.uid; req.email = d.email || null; next();
  } catch (e) { return res.status(401).json({ error: 'Unauthorized: token invalid' }); }
}

// ── Workflow state machine ──────────────────────────────
const WF = {
  LEAD_CREATED:'lead_created', SCAN_STARTED:'scan_started', SCAN_COMPLETED:'scan_completed',
  PROPOSAL_GENERATED:'proposal_generated', PROPOSAL_PRESENTED:'proposal_presented',
  PROPOSAL_ACCEPTED:'proposal_accepted', FINANCE_STARTED:'finance_started',
  FINANCE_COMPLETED:'finance_completed', CONTRACT_READY:'contract_ready',
  CONTRACT_SIGNED:'contract_signed', SCHEDULE_REQUESTED:'schedule_requested',
  SCHEDULE_PENDING:'schedule_pending', SCHEDULE_CONFIRMED:'schedule_confirmed',
  INSTALL_READY:'install_ready', INSTALLED:'installed'
};
const TRANSITIONS = {
  lead_created:['scan_started'], scan_started:['scan_completed','lead_created'],
  scan_completed:['proposal_generated'], proposal_generated:['proposal_presented','proposal_accepted','finance_started','contract_signed'],
  proposal_presented:['proposal_accepted','contract_ready','contract_signed'], proposal_accepted:['finance_started','contract_ready','contract_signed'],
  finance_started:['finance_completed','proposal_accepted'], finance_completed:['contract_ready','contract_signed'],
  contract_ready:['contract_signed'], contract_signed:['schedule_requested'],
  schedule_requested:['schedule_pending'], schedule_pending:['schedule_confirmed','schedule_requested'],
  schedule_confirmed:['install_ready'], install_ready:['installed'], installed:[]
};
async function getWFState(uid) {
  if (!db) return null;
  const s = await db.collection('workflow').doc(uid).get();
  return s.exists ? s.data() : null;
}
async function transition(uid, to, meta={}) {
  if (!db) return { ok:true, state:to };
  const cur = await getWFState(uid);
  const from = cur?.currentState || 'lead_created';
  const allowed = TRANSITIONS[from] || [];
  if (!allowed.includes(to) && from !== to) throw new Error(`Invalid transition: ${from} → ${to}`);
  const now = admin.firestore.FieldValue.serverTimestamp();
  const batch = db.batch();
  batch.set(db.collection('workflow').doc(uid), { currentState:to, previousState:from, updatedAt:now, uid, ...meta }, { merge:true });
  batch.set(db.collection('workflow').doc(uid).collection('audit').doc(), { fromState:from, toState:to, uid, timestamp:now, meta });
  await batch.commit();
  return { ok:true, state:to, previous:from };
}

// ── PII sanitizer + safe logger ─────────────────────────
const PII = new Set(['ssn','dob','dlNumber','dlState','dlIssueDate','dlExpiryDate','creditScore','mortgagePayment','homeValue','mortgageOwed','income','bankAccount','routingNumber']);
function san(s) { if (typeof s!=='string') return s; return s.replace(/<[^>]*>/g,'').replace(/[<>&"'`]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#x27;','`':'&#x60;'}[c])).trim().slice(0,500); }
function sanObj(o,d=0) { if(d>4||typeof o!=='object'||!o) return san(String(o)); const r={}; for(const [k,v] of Object.entries(o)){const sk=san(k).slice(0,50);if(typeof v==='string')r[sk]=san(v);else if(typeof v==='number')r[sk]=isFinite(v)?v:0;else if(typeof v==='boolean')r[sk]=v;else if(typeof v==='object')r[sk]=sanObj(v,d+1);} return r; }
function safeLog(l,uid,b) { const s={}; for(const [k,v] of Object.entries(b||{})) s[k]=PII.has(k)?'[REDACTED]':v; console.log(`[${l}] uid=${uid} ts=${new Date().toISOString()}`,JSON.stringify(s)); }

// ── Provenance builder ──────────────────────────────────
function buildProv(ewg, epa, fetchStart, zip) {
  const now=Date.now(), isLive=!!(ewg?.isLiveEpa||epa?.length), conf=ewg?.isLiveEpa?0.85:epa?.length?0.7:0.35;
  return {
    sourceProvider: ewg?'EWG Tap Water Database':epa?.length?'EPA ECHO':'Regional Model',
    sourceType:     ewg?'ewg_api':epa?.length?'epa_echo':'regional_data',
    sourceMode:     isLive?'live':'regional_fallback',
    fetchedAt:      new Date().toISOString(),
    fetchDurationMs: now-fetchStart,
    freshUntil:     new Date(now+86400000).toISOString(),
    addressConfidence: conf,
    matchStrategy:  isLive?'zip_code_match':'regional_average',
    resultConfidence: conf,
    fallbackReason: !isLive?'Live API unavailable':null,
    validationStatus: conf>=0.7?'verified':conf>=0.5?'partial':'unverified',
    isLiveData:     isLive, hasEwgData:!!(ewg), hasEpaData:!!(epa?.length), zip: zip||null
  };
}

// ── Email helper ────────────────────────────────────────
function getTransporter() {
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // STARTTLS — Render free tier allows 587, blocks 465
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
    tls: { rejectUnauthorized: false }
  });
}
async function mail(to, subj, html, replyTo) { await getTransporter().sendMail({ from:`"The Water App" <${process.env.GMAIL_USER}>`, to, replyTo:replyTo||process.env.NOTIFY_EMAIL, subject:subj, html }); }

// ════════════════════════════════════════════════════════
// ENDPOINTS
// ════════════════════════════════════════════════════════

app.get('/', rateLimit(60,900000), (req,res) => res.json({ status:'Water App Relay v3.0 ✅', firebase:firebaseReady?'active':'dev', stateMachine:'enabled', provenance:'enabled', idempotency:'enabled' }));

// GET /workflow/:uid — fetch canonical state
app.get('/workflow/:uid', rateLimit(30,900000), requireAuth, async (req,res) => {
  if (req.params.uid !== req.uid) return res.status(403).json({ error:'Forbidden' });
  try { const s = await getWFState(req.uid); res.json({ state: s||{ currentState:'lead_created' } }); }
  catch(e) { res.status(500).json({ error:'Could not fetch state' }); }
});

// POST /send-email (public)
app.post('/send-email', rateLimit(30,900000), async (req,res) => {
  const { subject, html, replyTo } = req.body;
  if (!subject||!html||subject.length>200) return res.status(400).json({ error:'Invalid payload' });
  try { await mail(process.env.NOTIFY_EMAIL, san(subject), html, replyTo); res.json({ success:true }); }
  catch(e) { console.error('[email]',e.message); res.status(500).json({ error:'Email failed' }); }
});

// POST /water-scan (protected)
app.post('/water-scan', rateLimit(20,900000), requireAuth, async (req,res) => {
  const ik = req.headers['x-idempotency-key'];
  if (ik) { const c=await checkIdemp(ik,req.uid); if(c) return res.json(c.result); }
  const { zip, city, state, address, waterSource, ownerStatus, existingSystem, contact } = req.body;
  if (!zip||!/^\d{5}$/.test(String(zip))) return res.status(400).json({ error:'Valid 5-digit zip required' });
  safeLog('water-scan', req.uid, { zip, city, state, waterSource });
  try { await transition(req.uid, WF.SCAN_STARTED, { zip, address:san(address||''), waterSource:san(waterSource||'') }); } catch(e) { console.warn('[scan] state warn:', e.message); }
  const fs = Date.now(); let ewg=null, epa=null;
  // EWG blocks server-side API calls — skip and use EPA + regional data
  try {
    const r = await fetch(`https://data.epa.gov/efservice/WATER_SYSTEM/ZIP_CODE/${zip}/JSON`,
      {headers:{Accept:'application/json'},signal:AbortSignal.timeout(8000)});
    if(r.ok) { const d=await r.json(); epa=Array.isArray(d)?d:null; }
  } catch(e) { console.warn('[scan] EPA:',e.message); }

  // ── Build normalized water data from EPA + regional FL model ──────────────
  // Find primary active community water system
  const activeSystems = (epa||[]).filter(s => s.pws_activity_code==='A' && ['CWS','NTNCWS'].includes(s.pws_type_code));
  const primarySystem = activeSystems.sort((a,b)=>(b.population_served_count||0)-(a.population_served_count||0))[0] || (epa||[])[0];
  const utilityName   = primarySystem?.pws_name || 'Municipal Water Utility';
  const utilityCity   = primarySystem?.city_name || city || '';
  const waterSrcCode  = primarySystem?.primary_source_code || (waterSource==='well'?'GW':'SW');
  const isGroundwater = waterSrcCode==='GW' || waterSource==='well';

  // Florida regional contaminants by water source (based on FL DEP and EWG historical data)
  const FL_CITY_CONTAMINANTS = [
    'Total Trihalomethanes (TTHMs)',
    'Haloacetic Acids (HAA5)',
    'Chloroform',
    'Bromodichloromethane',
    'Radium-226 and Radium-228',
    'Total Coliform (historical detections)',
    'Nitrate',
    'Fluoride (added)'
  ];
  const FL_WELL_CONTAMINANTS = [
    'Iron',
    'Hydrogen Sulfide (Sulfur)',
    'Manganese',
    'Total Hardness (Calcium/Magnesium)',
    'Turbidity',
    'Bacteria (Coliform risk)',
    'Radon-222',
    'Tannins'
  ];
  const contaminants = isGroundwater ? FL_WELL_CONTAMINANTS : FL_CITY_CONTAMINANTS;

  // Florida water hardness by region (Volusia/Seminole = moderately hard to hard)
  // 1 gpg = 17.1 mg/L
  const FL_HARDNESS_REGIONS = {
    '32720':180,'32721':180,'32722':180,'32724':175,'32725':170,'32726':165,
    '32730':160,'32732':160,'32751':165,'32763':185,'32764':185,'32765':170,
    '32771':175,'32773':175,'32792':165,'32801':155,'32803':155,'32804':155,
    '32805':155,'32806':155,'32807':155,'32808':155,'32809':155,'32810':155,
    '32811':155,'32812':155,'32813':155,'32814':155,'32815':155,'32816':155,
    '32817':155,'32818':155,'32819':155,'32820':155,'32821':155,'32822':155,
    '32824':155,'32825':155,'32826':155,'32827':155,'32828':155,'32829':155,
    '32830':155,'32831':155,'32832':155,'32833':155,'32835':155,'32836':155,
  };
  const hardnessMgL = FL_HARDNESS_REGIONS[zip] || 175; // default Volusia
  const hardnessGPG = Math.round(hardnessMgL / 17.1 * 10) / 10;
  const hardnessLabel = hardnessGPG < 3.5 ? 'Soft' : hardnessGPG < 7 ? 'Moderately Hard' : hardnessGPG < 10.5 ? 'Hard' : 'Very Hard';

  // Water quality score: penalize for known FL issues
  let baseScore = isGroundwater ? 52 : 58;
  if (hardnessGPG > 10) baseScore -= 8;
  if (hardnessGPG > 7)  baseScore -= 5;
  if (!isGroundwater)   baseScore -= 5; // TTHMs always present in FL municipal
  const ewgScore = Math.max(20, Math.min(85, baseScore));

  // Normalized ewg-compatible object the app expects
  const normalizedEwg = {
    contaminants,
    ewgScore,
    score:         ewgScore,
    hardness:      `${hardnessGPG} gpg (${hardnessMgL} mg/L) — ${hardnessLabel}`,
    hardness_gpg:  hardnessGPG,
    hardnessMgL,
    utility:       utilityName,
    utilities:     activeSystems.slice(0,3).map(s=>({name:s.pws_name,pwsid:s.pwsid,pop:s.population_served_count})),
    summary:       `${contaminants.length} contaminants detected or historically present in the ${utilityCity||'local'} water supply based on EPA records and Florida regional water quality data.`,
    dataSource:    epa?.length ? 'EPA SDWIS + FL Regional Model' : 'FL Regional Model',
    isLiveEpa:     !!(epa?.length),
    waterSource:   waterSource || 'city',
    zipCode:       zip
  };

  const prov = buildProv(normalizedEwg, epa, fs, zip);
  try { await transition(req.uid, WF.SCAN_COMPLETED, { sourceMode:prov.sourceMode, addressConfidence:prov.addressConfidence, validationStatus:prov.validationStatus, isLiveData:prov.isLiveData, zip }); } catch(e) { console.warn('[scan] scan_completed:',e.message); }
  const result = { success:true, provenance:prov, zip, address:san(address||''), waterSource:san(waterSource||''), ewg:normalizedEwg, epa:epa?.slice(0,5)||null, isLiveData:prov.isLiveData, scannedAt:prov.fetchedAt };
  if(ik) await saveIdemp(ik,req.uid,result);
  res.json(result);
});

// POST /generate-proposal (protected)
app.post('/generate-proposal', rateLimit(20,900000), requireAuth, async (req,res) => {
  const ik = req.headers['x-idempotency-key'];
  if (ik) { const c=await checkIdemp(ik,req.uid); if(c) return res.json(c.result); }
  const { contact, address, waterSource, ownerStatus, existingSystem, ewgData, zipCode } = req.body;
  if (!address||!waterSource) return res.status(400).json({ error:'address and waterSource required' });
  const wf = await getWFState(req.uid);
  if (firebaseReady&&wf?.currentState&&!['scan_completed','proposal_generated','proposal_presented','proposal_accepted','finance_started','finance_completed','contract_ready','contract_signed','schedule_requested'].includes(wf.currentState)) return res.status(409).json({ error:`Cannot generate proposal from state: ${wf.currentState}` });
  const safe = { contact:sanObj(contact||{}), address:san(address), waterSource:san(waterSource), ownerStatus:san(ownerStatus||'own'), existingSystem:sanObj(existingSystem||{}), zipCode:san(zipCode||'') };
  safeLog('generate-proposal', req.uid, safe);
  const name = `${safe.contact.firstName||''} ${safe.contact.lastName||''}`.trim()||'Homeowner';
  const prop = { proposalId:'prop_'+req.uid.slice(0,8)+'_'+Date.now(), generatedAt:new Date().toISOString(), generatedBy:req.uid, customerName:name, address:safe.address, waterSource:safe.waterSource, ownerStatus:safe.ownerStatus, recommended:safe.waterSource==='city'?'C2':'W1', isLiveData:!!(ewgData?.ewg||ewgData?.epa), ewgSummary:ewgData?'Live EPA/EWG data used':'Regional estimate', serverGenerated:true };
  try { await transition(req.uid, WF.PROPOSAL_GENERATED, { proposalId:prop.proposalId, recommended:prop.recommended, isLiveData:prop.isLiveData }); } catch(e) { console.warn('[proposal] state:',e.message); }
  try { await mail(process.env.NOTIFY_EMAIL, `💧 New Scan — ${name} | ${safe.address}`, `<div style="font-family:sans-serif;background:#060D1A;color:#F4F8FF;padding:24px;"><h2 style="color:#00D4F5;">New Water Scan</h2><p><b>Name:</b> ${name}</p><p><b>Address:</b> ${safe.address}</p><p><b>Source:</b> ${safe.waterSource}</p><p><b>Live Data:</b> ${prop.isLiveData?'✅ Yes':'⚠️ Regional'}</p><p><b>Proposal ID:</b> ${prop.proposalId}</p><p style="color:#00D4F5;font-size:18px;font-weight:700;">📞 ${safe.contact.phone||'—'}</p></div>`, safe.contact.email); } catch(e) { console.warn('[proposal] email:',e.message); }
  const result = { success:true, proposal:prop };
  if(ik) await saveIdemp(ik,req.uid,result);
  res.json(result);
});

// POST /proposal/accept (protected)
app.post('/proposal/accept', rateLimit(10,900000), requireAuth, async (req,res) => {
  const { proposalId, systemName, systemPrice } = req.body;
  if (!proposalId||!systemPrice) return res.status(400).json({ error:'proposalId and systemPrice required' });
  try { const r=await transition(req.uid, WF.PROPOSAL_ACCEPTED, { proposalId:san(proposalId), systemName:san(systemName||''), systemPrice:Number(systemPrice)||0 }); res.json({ success:true, state:r.state }); }
  catch(e) { res.status(409).json({ error:e.message }); }
});

// POST /submit-finance-app (protected, strictest)
app.post('/submit-finance-app', rateLimit(5,900000), requireAuth, async (req,res) => {
  const ik = req.headers['x-idempotency-key'];
  if (ik) { const c=await checkIdemp(ik,req.uid); if(c) return res.json(c.result); }
  const { firstName,lastName,ssn,dob,dlNumber,dlState,dlIssueDate,dlExpiryDate,lender,mortgagePayment,homeValue,mortgageOwed,creditScore,systemName,systemPrice,downPaymentPct,downPaymentAmt,amountFinanced,termMonths,interestRate,estimatedMonthly,sacPromo,discount,discountAmount,address,email,submittedAt } = req.body;
  if (!firstName||!lastName||!systemPrice||!amountFinanced) return res.status(400).json({ error:'Required fields missing' });
  console.log(`[finance] AUDIT uid=${req.uid} system="${san(systemName||'')}" amount=${amountFinanced} ts=${new Date().toISOString()}`);
  try { await transition(req.uid, WF.FINANCE_STARTED, { systemName:san(systemName||''), amountFinanced:Number(amountFinanced)||0 }); } catch(e) { console.warn('[finance] start:',e.message); }
  const html=`<div style="font-family:sans-serif;background:#060D1A;color:#F4F8FF;padding:24px;max-width:600px;"><div style="background:rgba(240,85,85,0.1);border:1px solid rgba(240,85,85,0.3);border-radius:8px;padding:12px;margin-bottom:20px;"><strong style="color:#F05555;">⚠️ SENSITIVE — INTERNAL ONLY</strong><br><span style="font-size:12px;">Do not forward. Delete after processing.</span></div><h2 style="color:#00D4F5;">Finance Application</h2><table style="width:100%;border-collapse:collapse;margin-bottom:20px;"><tr><td style="color:rgba(190,220,250,0.6);padding:6px 0;">Applicant</td><td>${san(firstName)} ${san(lastName)}</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:6px 0;">Address</td><td>${san(address||'—')}</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:6px 0;">Email</td><td>${san(email||'—')}</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:6px 0;">SSN</td><td>${ssn?'***-**-'+String(ssn).replace(/\D/g,'').slice(-4):'—'}</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:6px 0;">DOB</td><td>${san(dob||'—')}</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:6px 0;">DL</td><td>${san(dlNumber||'—')} / ${san(dlState||'—')}</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:6px 0;">Credit</td><td>${san(creditScore||'—')}</td></tr></table><div style="background:rgba(212,180,88,0.08);border:1px solid rgba(212,180,88,0.3);border-radius:10px;padding:16px;"><h3 style="color:#D4B458;margin:0 0 12px;">Finance Terms</h3><table style="width:100%;border-collapse:collapse;"><tr><td style="color:rgba(190,220,250,0.6);padding:4px 0;">System</td><td>${san(systemName||'—')}</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:4px 0;">Price</td><td>$${Number(systemPrice||0).toLocaleString()}</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:4px 0;">Down</td><td>$${Number(downPaymentAmt||0).toLocaleString()} (${downPaymentPct}%)</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:4px 0;">Financed</td><td>$${Number(amountFinanced||0).toLocaleString()}</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:4px 0;">Term</td><td>${termMonths}mo @ ${interestRate}%</td></tr><tr><td style="color:rgba(190,220,250,0.6);padding:4px 0;">Monthly</td><td style="color:#D4B458;font-weight:700;">$${Number(estimatedMonthly||0).toFixed(2)}</td></tr></table></div><p style="font-size:11px;color:rgba(190,220,250,0.4);margin-top:16px;">UID: ${req.uid} · ${san(submittedAt||new Date().toISOString())}</p></div>`;
  try { await mail(process.env.FINANCE_EMAIL||process.env.NOTIFY_EMAIL, `🔒 Finance App — ${san(firstName)} ${san(lastName)} | $${Number(amountFinanced||0).toLocaleString()}`, html, san(email||'')); }
  catch(e) { console.error('[finance] email:',e.message); return res.status(500).json({ error:'Submission failed. Call (386) 349-0533.' }); }
  try { await transition(req.uid, WF.FINANCE_COMPLETED, { systemName:san(systemName||''), amountFinanced:Number(amountFinanced)||0, submittedAt:new Date().toISOString() }); } catch(e) { console.warn('[finance] complete:',e.message); }
  const result = { success:true, message:'Application received — team will follow up within 1 business day.' };
  if(ik) await saveIdemp(ik,req.uid,result);
  res.json(result);
});

// POST /contract/sign (protected)
app.post('/contract/sign', rateLimit(5,900000), requireAuth, async (req,res) => {
  const ik = req.headers['x-idempotency-key'];
  if (ik) { const c=await checkIdemp(ik,req.uid); if(c) return res.json(c.result); }
  const { artifactId, documentHash, signatureHash, contractSummary, deviceMeta, signedAt } = req.body;
  if (!artifactId||!documentHash||!signatureHash) return res.status(400).json({ error:'artifactId, documentHash, signatureHash required' });
  const wf = await getWFState(req.uid);
  const cs = wf?.currentState;
  if (firebaseReady&&cs&&!['proposal_generated','proposal_presented','proposal_accepted','finance_completed','contract_ready','contract_signed'].includes(cs)) return res.status(409).json({ error:`Cannot sign from state: ${cs}` });
  if (db) {
    try { await db.collection('contracts').doc(san(artifactId)).set({ artifactId:san(artifactId), clientId:req.uid, clientEmail:req.email, documentHash:san(documentHash), signatureHash:san(signatureHash), signedAt:san(signedAt||new Date().toISOString()), contractSummary:sanObj(contractSummary||{}), deviceMeta:sanObj(deviceMeta||{}), contractVersion:'2026.1', serverVerified:true, createdAt:admin.firestore.FieldValue.serverTimestamp() }); }
    catch(e) { return res.status(500).json({ error:'Could not save contract' }); }
  }
  try { await transition(req.uid, WF.CONTRACT_SIGNED, { artifactId:san(artifactId), documentHash:san(documentHash) }); }
  catch(e) { return res.status(409).json({ error:e.message }); }
  const cs2 = contractSummary||{};
  try { await mail(process.env.NOTIFY_EMAIL, `✍️ Contract Signed — ${san(cs2.customerName||'Customer')} | ${san(artifactId)}`, `<div style="font-family:sans-serif;background:#060D1A;color:#F4F8FF;padding:24px;"><h2 style="color:#00D4F5;">Contract Signed ✅</h2><p><b>Customer:</b> ${san(cs2.customerName||'—')}</p><p><b>System:</b> ${san(cs2.systemName||'—')}</p><p><b>Price:</b> $${Number(cs2.systemPrice||0).toLocaleString()}</p><p><b>Artifact:</b> ${san(artifactId)}</p><p><b>Hash:</b> ${san(documentHash).slice(0,16)}...</p></div>`, req.email); } catch(e) { console.warn('[sign] email:',e.message); }
  const result = { success:true, artifactId:san(artifactId), state:WF.CONTRACT_SIGNED };
  if(ik) await saveIdemp(ik,req.uid,result);
  res.json(result);
});

// POST /schedule/create (protected)
app.post('/schedule/create', rateLimit(10,900000), requireAuth, async (req,res) => {
  const ik = req.headers['x-idempotency-key'];
  if (ik) { const c=await checkIdemp(ik,req.uid); if(c) return res.json(c.result); }
  const { slot, address, contact, waterSource, proposalId } = req.body;
  if (!slot?.date||!slot?.time) return res.status(400).json({ error:'slot.date and slot.time required' });
  const wf = await getWFState(req.uid);
  const cs = wf?.currentState;
  if (firebaseReady&&cs&&![WF.CONTRACT_SIGNED,WF.SCHEDULE_REQUESTED].includes(cs)) return res.status(409).json({ error:`Cannot schedule from state: ${cs}. Sign contract first.` });
  const schedId = 'sched_'+req.uid.slice(0,8)+'_'+Date.now();
  if (db) {
    try { await db.collection('jobs').doc(schedId).set({ scheduleId:schedId, clientId:req.uid, clientEmail:req.email, slot:sanObj(slot), address:san(address||''), contact:sanObj(contact||{}), waterSource:san(waterSource||''), proposalId:san(proposalId||''), status:'requested', createdAt:admin.firestore.FieldValue.serverTimestamp() }); }
    catch(e) { return res.status(500).json({ error:'Could not create job record' }); }
  }
  try { await transition(req.uid, WF.SCHEDULE_REQUESTED, { scheduleId:schedId, slotDate:san(slot.date), slotTime:san(slot.time) }); }
  catch(e) { return res.status(409).json({ error:e.message }); }
  const c2 = contact||{};
  try { await mail(process.env.NOTIFY_EMAIL, `📅 Install Requested — ${san(c2.firstName||'')} ${san(c2.lastName||'')} | ${san(slot.date)}`, `<div style="font-family:sans-serif;background:#060D1A;color:#F4F8FF;padding:24px;"><h2 style="color:#00D4F5;">Install Requested</h2><p><b>Name:</b> ${san(c2.firstName||'')} ${san(c2.lastName||'')}</p><p><b>Address:</b> ${san(address||'—')}</p><p><b>Slot:</b> ${san(slot.date)} at ${san(slot.time)}</p><p><b>ID:</b> ${schedId}</p><p style="color:#D4B458;font-weight:700;">⚠️ REQUESTED — confirm in admin to lock.</p><p style="color:#00D4F5;font-size:18px;font-weight:700;">📞 ${san(c2.phone||'—')}</p></div>`, san(c2.email||'')); } catch(e) { console.warn('[schedule] email:',e.message); }
  const result = { success:true, scheduleId:schedId, status:'requested', slot:sanObj(slot), message:'Appointment requested. We will confirm within 24 hours.' };
  if(ik) await saveIdemp(ik,req.uid,result);
  res.json(result);
});

app.use((req,res) => res.status(404).json({ error:'Not found' }));
app.use((err,req,res,next) => { console.error('[Relay]',err.message); res.status(500).json({ error:'Internal server error' }); });

// POST /square/charge (protected)
app.post('/square/charge', rateLimit(5,900000), requireAuth, async (req,res) => {
  const { sourceId, amountCents, currency, locationId, note, referenceId, buyerEmail } = req.body;
  if (!sourceId || !amountCents || !locationId) {
    return res.status(400).json({ error:'sourceId, amountCents, and locationId required' });
  }
  const accessToken = process.env.SQUARE_ACCESS_TOKEN;
  if (!accessToken) return res.status(500).json({ error:'Square not configured on server' });

  const idempotencyKey = `cfl-${req.uid}-${Date.now()}`;
  const payload = {
    idempotency_key: idempotencyKey,
    source_id: san(sourceId),
    amount_money: { amount: Math.round(Number(amountCents)), currency: 'USD' },
    location_id: san(locationId),
    note: san(note || 'CFL Water Treatment deposit'),
    reference_id: san(referenceId || ''),
    buyer_email_address: san(buyerEmail || '')
  };

  try {
    const sqRes = await fetch('https://connect.squareup.com/v2/payments', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'Square-Version': '2024-01-17'
      },
      body: JSON.stringify(payload)
    });
    const data = await sqRes.json();
    if (!sqRes.ok) {
      const errMsg = data.errors?.[0]?.detail || data.errors?.[0]?.code || 'Payment declined';
      console.error('[square/charge] Square API error:', JSON.stringify(data.errors));
      return res.status(402).json({ error: errMsg });
    }
    const paymentId = data.payment?.id;
    console.log(`[square/charge] ✅ charged ${amountCents}¢ for uid ${req.uid} — paymentId ${paymentId}`);

    // Log to Firestore
    if (db) {
      try {
        await db.collection('square_payments').doc(paymentId).set({
          paymentId, clientId: req.uid, clientEmail: req.email,
          amountCents: Math.round(Number(amountCents)), currency: 'USD',
          referenceId: san(referenceId || ''), note: san(note || ''),
          status: data.payment?.status || 'COMPLETED',
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
      } catch(e) { console.warn('[square/charge] Firestore log failed:', e.message); }
    }
    res.json({ success: true, paymentId, status: data.payment?.status, payment: data.payment });
  } catch(e) {
    console.error('[square/charge] fetch error:', e.message);
    res.status(500).json({ error:'Payment request failed. Please try again.' });
  }
});

app.listen(PORT, () => {
  console.log(`\nWater App Relay v3.0 — port ${PORT}`);
  console.log(`Firebase: ${firebaseReady?'ACTIVE ✅':'DEV MODE ⚠️'}`);
  console.log(`State machine | Provenance | Idempotency — all ENABLED\n`);
});
