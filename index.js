require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const nodemailer = require('nodemailer');
const fetch      = require('node-fetch');
const admin      = require('firebase-admin');
const { SquareClient, SquareEnvironment, SquareError } = require('square');

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

// ── Square Client ───────────────────────────────────────
let squareReady = false;
let squarePayments = null;
let squareCustomers = null;
let squareCards = null;
try {
  if (process.env.SQUARE_ACCESS_TOKEN) {
    const squareClient = new SquareClient({
      token: process.env.SQUARE_ACCESS_TOKEN,
      environment: SquareEnvironment.Production
    });
    squarePayments  = squareClient.payments;
    squareCustomers = squareClient.customers;
    squareCards     = squareClient.cards;
    squareReady     = true;
    console.log('[Relay] Square ✅');
  } else {
    console.warn('[Relay] No SQUARE_ACCESS_TOKEN — Square disabled');
  }
} catch (e) { console.error('[Relay] Square init failed:', e.message); }

// ── CORS ────────────────────────────────────────────────
const ALLOWED = [
  'https://the-water-app.netlify.app',
  'https://cfl-twa-admin.netlify.app',
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

// ── Admin middleware ────────────────────────────────────
const ADMIN_EMAILS = [
  'brandonthewaterman@gmail.com',
  'admin@cflwatertreatment.com'
];
async function requireAdmin(req, res, next) {
  await requireAuth(req, res, async () => {
    if (!firebaseReady) return next(); // dev bypass
    if (!req.email || !ADMIN_EMAILS.includes(req.email.toLowerCase())) {
      return res.status(403).json({ error: 'Forbidden: admin only' });
    }
    next();
  });
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
  const now=Date.now(), isLive=!!(ewg||epa?.length), conf=ewg?0.9:epa?.length?0.7:0.2;
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
    secure: false,
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
    tls: { rejectUnauthorized: false }
  });
}
async function mail(to, subj, html, replyTo) { await getTransporter().sendMail({ from:`"The Water App" <${process.env.GMAIL_USER}>`, to, replyTo:replyTo||process.env.NOTIFY_EMAIL, subject:subj, html }); }

// ── Square amount helper ────────────────────────────────
// Square works in cents (integers). Prices in our app are dollars.
function toCents(dollars) {
  return Math.round(Number(dollars) * 100);
}

// ════════════════════════════════════════════════════════
// ENDPOINTS
// ════════════════════════════════════════════════════════

app.get('/', rateLimit(60,900000), (req,res) => res.json({
  status:'Water App Relay v3.1 ✅',
  firebase: firebaseReady ? 'active' : 'dev',
  square:   squareReady   ? 'active' : 'disabled',
  stateMachine:'enabled', provenance:'enabled', idempotency:'enabled'
}));

// GET /workflow/:uid
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
  try { const r=await fetch(`https://www.ewg.org/tapwater/api/zip/?zip=${zip}`,{headers:{Accept:'application/json','User-Agent':'CFL-WaterApp/3.0'},timeout:8000}); if(r.ok) ewg=await r.json(); } catch(e) { console.warn('[scan] EWG:',e.message); }
  try { const r=await fetch(`https://data.epa.gov/efservice/WATER_SYSTEM/ZIP_CODE/${zip}/JSON`,{headers:{Accept:'application/json'},timeout:8000}); if(r.ok){const d=await r.json();epa=Array.isArray(d)?d.slice(0,5):null;} } catch(e) { console.warn('[scan] EPA:',e.message); }
  const prov = buildProv(ewg, epa, fs, zip);
  try { await transition(req.uid, WF.SCAN_COMPLETED, { sourceMode:prov.sourceMode, addressConfidence:prov.addressConfidence, validationStatus:prov.validationStatus, isLiveData:prov.isLiveData, zip }); } catch(e) { console.warn('[scan] scan_completed:',e.message); }
  const result = { success:true, provenance:prov, zip, address:san(address||''), waterSource:san(waterSource||''), ewg, epa, isLiveData:prov.isLiveData, scannedAt:prov.fetchedAt };
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
  if (firebaseReady&&wf?.currentState&&!['scan_completed','proposal_generated','proposal_presented'].includes(wf.currentState)) return res.status(409).json({ error:`Cannot generate proposal from state: ${wf.currentState}` });
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

// ── Square: POST /square/save-card (protected, customer-facing) ─
// Called after customer tokenizes card on payment screen.
// Creates Square Customer + saves card on file.
// Stores squareCustomerId + squareCardId in Firestore contracts doc.
app.post('/square/save-card', rateLimit(5,900000), requireAuth, async (req,res) => {
  if (!squareReady) return res.status(503).json({ error:'Payment processing unavailable' });
  const { sourceId, artifactId, customerName, customerEmail, customerPhone, billingAddress } = req.body;
  if (!sourceId || !artifactId || !customerName || !customerEmail) {
    return res.status(400).json({ error:'sourceId, artifactId, customerName, customerEmail required' });
  }

  try {
    // 1. Create Square Customer
    const custResp = await squareCustomers.createCustomer({
      idempotencyKey: `cust_${req.uid}_${Date.now()}`,
      givenName:  san(customerName.split(' ')[0] || customerName),
      familyName: san(customerName.split(' ').slice(1).join(' ') || ''),
      emailAddress: san(customerEmail),
      phoneNumber:  san(customerPhone || ''),
      address: billingAddress ? {
        addressLine1: san(billingAddress.line1 || ''),
        locality:     san(billingAddress.city  || ''),
        administrativeDistrictLevel1: san(billingAddress.state || 'FL'),
        postalCode:   san(billingAddress.zip   || ''),
        country: 'US'
      } : undefined,
      note: `Water App — UID: ${req.uid} | Artifact: ${san(artifactId)}`
    });

    const squareCustomerId = custResp.result.customer.id;

    // 2. Save card on file against that customer
    const cardResp = await squareCards.createCard({
      idempotencyKey: `card_${req.uid}_${Date.now()}`,
      sourceId: san(sourceId),
      card: {
        customerId: squareCustomerId,
        billingAddress: billingAddress ? {
          addressLine1: san(billingAddress.line1 || ''),
          locality:     san(billingAddress.city  || ''),
          administrativeDistrictLevel1: san(billingAddress.state || 'FL'),
          postalCode:   san(billingAddress.zip   || ''),
          country: 'US'
        } : undefined
      }
    });

    const card = cardResp.result.card;
    const squareCardId  = card.id;
    const last4         = card.last4;
    const cardBrand     = card.cardBrand; // VISA, MASTERCARD, etc.

    // 3. Store in Firestore contracts doc (merge so existing sign data survives)
    if (db) {
      await db.collection('contracts').doc(san(artifactId)).set({
        squareCustomerId,
        squareCardId,
        cardLast4:  last4,
        cardBrand,
        cardSavedAt: admin.firestore.FieldValue.serverTimestamp(),
        cardSavedBy: req.uid
      }, { merge: true });
    }

    console.log(`[square] card saved uid=${req.uid} artifact=${artifactId} last4=${last4} brand=${cardBrand}`);
    res.json({ success:true, last4, cardBrand });

  } catch (e) {
    // Square SDK wraps errors in SquareError
    if (e instanceof SquareError) {
      const msg = e.errors?.[0]?.detail || 'Card save failed';
      console.error('[square/save-card] SquareError:', msg);
      return res.status(400).json({ error: msg });
    }
    console.error('[square/save-card]', e.message);
    res.status(500).json({ error:'Card save failed — please try again' });
  }
});

// ── Square: POST /square/charge (admin-only, manual trigger) ────
// Brandon taps "Charge Deposit" or "Charge Balance" in admin panel.
// Looks up squareCustomerId + squareCardId from Firestore contracts doc.
// Fires the charge. Logs result back to Firestore.
app.post('/square/charge', rateLimit(10,900000), requireAdmin, async (req,res) => {
  if (!squareReady) return res.status(503).json({ error:'Payment processing unavailable' });
  const { artifactId, chargeType, amountDollars, note } = req.body;
  // chargeType: 'deposit' | 'balance'
  if (!artifactId || !chargeType || !amountDollars) {
    return res.status(400).json({ error:'artifactId, chargeType, amountDollars required' });
  }
  if (!['deposit','balance'].includes(chargeType)) {
    return res.status(400).json({ error:'chargeType must be deposit or balance' });
  }
  const amountCents = toCents(amountDollars);
  if (amountCents < 100) return res.status(400).json({ error:'Minimum charge is $1.00' });

  try {
    // Fetch card credentials from Firestore
    if (!db) return res.status(503).json({ error:'Database unavailable' });
    const contractDoc = await db.collection('contracts').doc(san(artifactId)).get();
    if (!contractDoc.exists) return res.status(404).json({ error:'Contract not found' });
    const contractData = contractDoc.data();

    const { squareCustomerId, squareCardId, cardLast4, cardBrand } = contractData;
    if (!squareCustomerId || !squareCardId) {
      return res.status(400).json({ error:'No card on file for this contract. Customer must save card first.' });
    }

    // Check not already charged for this type
    if (chargeType === 'deposit' && contractData.depositChargedAt) {
      return res.status(409).json({ error:'Deposit already charged', chargedAt: contractData.depositChargedAt });
    }
    if (chargeType === 'balance' && contractData.balanceChargedAt) {
      return res.status(409).json({ error:'Balance already charged', chargedAt: contractData.balanceChargedAt });
    }

    // Fire payment
    const chargeResp = await squarePayments.createPayment({
      idempotencyKey: `${chargeType}_${san(artifactId)}_${Date.now()}`,
      sourceId: squareCardId,
      customerId: squareCustomerId,
      amountMoney: {
        amount: BigInt(amountCents),
        currency: 'USD'
      },
      locationId: process.env.SQUARE_LOCATION_ID,
      note: san(note || `CFL Water Treatment — ${chargeType === 'deposit' ? 'Deposit' : 'Balance'} | ${san(artifactId)}`)
    });

    const payment    = chargeResp.result.payment;
    const paymentId  = payment.id;
    const payStatus  = payment.status; // COMPLETED, APPROVED, etc.
    const receiptUrl = payment.receiptUrl || null;

    // Log back to Firestore
    const updateField = chargeType === 'deposit' ? {
      depositPaymentId:  paymentId,
      depositAmountCents: amountCents,
      depositStatus:     payStatus,
      depositReceiptUrl: receiptUrl,
      depositChargedAt:  admin.firestore.FieldValue.serverTimestamp(),
      depositChargedBy:  req.email
    } : {
      balancePaymentId:  paymentId,
      balanceAmountCents: amountCents,
      balanceStatus:     payStatus,
      balanceReceiptUrl: receiptUrl,
      balanceChargedAt:  admin.firestore.FieldValue.serverTimestamp(),
      balanceChargedBy:  req.email
    };

    await db.collection('contracts').doc(san(artifactId)).set(updateField, { merge: true });

    // Notify Brandon by email
    const customerName = contractData.contractSummary?.customerName || 'Customer';
    const systemName   = contractData.contractSummary?.systemName   || 'System';
    try {
      await mail(
        process.env.NOTIFY_EMAIL,
        `💳 ${chargeType === 'deposit' ? 'Deposit' : 'Balance'} Charged — ${san(customerName)} | $${Number(amountDollars).toLocaleString()}`,
        `<div style="font-family:sans-serif;background:#060D1A;color:#F4F8FF;padding:24px;">
          <h2 style="color:#00D4F5;">Payment ${payStatus} ✅</h2>
          <p><b>Type:</b> ${chargeType === 'deposit' ? 'Deposit (50%)' : 'Balance (50%)'}</p>
          <p><b>Customer:</b> ${san(customerName)}</p>
          <p><b>System:</b> ${san(systemName)}</p>
          <p><b>Amount:</b> $${Number(amountDollars).toLocaleString()}</p>
          <p><b>Card:</b> ${san(cardBrand||'')} ····${san(cardLast4||'')}</p>
          <p><b>Payment ID:</b> ${paymentId}</p>
          ${receiptUrl ? `<p><a href="${receiptUrl}" style="color:#00D4F5;">View Receipt →</a></p>` : ''}
          <p><b>Charged by:</b> ${san(req.email)}</p>
        </div>`
      );
    } catch(e) { console.warn('[square/charge] email:', e.message); }

    console.log(`[square] charge fired uid=${req.uid} artifact=${artifactId} type=${chargeType} amount=${amountCents}c paymentId=${paymentId} status=${payStatus}`);
    res.json({ success:true, paymentId, status:payStatus, receiptUrl, amountDollars, chargeType });

  } catch (e) {
    if (e instanceof SquareError) {
      const msg = e.errors?.[0]?.detail || 'Charge failed';
      console.error('[square/charge] SquareError:', msg);
      return res.status(400).json({ error: msg });
    }
    console.error('[square/charge]', e.message);
    res.status(500).json({ error:'Charge failed — check Square dashboard' });
  }
});

app.use((req,res) => res.status(404).json({ error:'Not found' }));
app.use((err,req,res,next) => { console.error('[Relay]',err.message); res.status(500).json({ error:'Internal server error' }); });

app.listen(PORT, () => {
  console.log(`\nWater App Relay v3.1 — port ${PORT}`);
  console.log(`Firebase: ${firebaseReady?'ACTIVE ✅':'DEV MODE ⚠️'}`);
  console.log(`Square:   ${squareReady  ?'ACTIVE ✅':'DISABLED ⚠️'}`);
  console.log(`State machine | Provenance | Idempotency — all ENABLED\n`);
});
