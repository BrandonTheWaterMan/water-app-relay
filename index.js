require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const nodemailer = require('nodemailer');
const fetch   = require('node-fetch');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

/* ─── Health Check ──────────────────────────────────────── */
app.get('/', (req, res) => {
  res.json({ status: 'Water App Relay is live ✅', version: '1.0.0' });
});

/* ─── Nodemailer Transporter ────────────────────────────── */
function getTransporter() {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS
    }
  });
}

/* ═══════════════════════════════════════════════════════════
   POST /send-email
   Generic email endpoint — fires on every app submit event
   Body: { subject, html, replyTo? }
═══════════════════════════════════════════════════════════ */
app.post('/send-email', async (req, res) => {
  const { subject, html, replyTo } = req.body;

  if (!subject || !html) {
    return res.status(400).json({ error: 'subject and html are required' });
  }

  try {
    const transporter = getTransporter();
    await transporter.sendMail({
      from:    `"The Water App" <${process.env.GMAIL_USER}>`,
      to:      process.env.NOTIFY_EMAIL,
      replyTo: replyTo || process.env.NOTIFY_EMAIL,
      subject,
      html
    });
    res.json({ success: true });
  } catch (err) {
    console.error('Email error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/* ═══════════════════════════════════════════════════════════
   POST /water-scan
   Pulls EWG + EPA data by address / zip
   Body: { address, city, state, zip }
═══════════════════════════════════════════════════════════ */
app.post('/water-scan', async (req, res) => {
  const { address, city, state, zip } = req.body;

  if (!zip) {
    return res.status(400).json({ error: 'zip is required' });
  }

  try {
    /* EWG Tap Water Database — public endpoint */
    const ewgUrl = `https://www.ewg.org/tapwater/api/zip/?zip=${zip}`;
    const ewgRes = await fetch(ewgUrl, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'WaterApp/1.0' }
    });

    let ewgData = null;
    if (ewgRes.ok) {
      ewgData = await ewgRes.json();
    }

    /* EPA ECHO — water system lookup by zip */
    const epaUrl = `https://data.epa.gov/efservice/WATER_SYSTEM/ZIP_CODE/${zip}/JSON`;
    const epaRes = await fetch(epaUrl, {
      headers: { 'Accept': 'application/json' }
    });

    let epaData = null;
    if (epaRes.ok) {
      epaData = await epaRes.json();
    }

    res.json({
      success: true,
      zip,
      address: `${address || ''}, ${city || ''}, ${state || 'FL'} ${zip}`,
      ewg: ewgData,
      epa: epaData ? epaData.slice(0, 5) : null   // cap at 5 systems
    });

  } catch (err) {
    console.error('Water scan error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

/* ═══════════════════════════════════════════════════════════
   POST /generate-proposal
   Accepts customer + cost data, returns proposal HTML
   Body: { name, address, email, phone, waterSource,
           annualCost, sliders, waterScanData }
═══════════════════════════════════════════════════════════ */
app.post('/generate-proposal', async (req, res) => {
  const {
    name, address, email, phone,
    waterSource, annualCost, sliders, waterScanData
  } = req.body;

  if (!name || !annualCost) {
    return res.status(400).json({ error: 'name and annualCost are required' });
  }

  const lifetimeCost = (parseFloat(annualCost) * 10).toLocaleString();
  const annual       = parseFloat(annualCost).toLocaleString();
  const date         = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric'
  });

  const sliderRows = sliders ? Object.entries(sliders).map(([key, val]) =>
    `<tr>
      <td style="padding:6px 12px;border-bottom:1px solid #1a2a3a;color:#8ab4cc;">${key}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #1a2a3a;color:#D4B458;text-align:right;">$${parseFloat(val).toLocaleString()}/yr</td>
    </tr>`
  ).join('') : '';

  const proposalHtml = `
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"><title>Water Quality Proposal — ${name}</title></head>
    <body style="margin:0;padding:0;background:#060D1A;font-family:'Segoe UI',sans-serif;color:#F4F8FF;">
      <div style="max-width:600px;margin:0 auto;padding:32px 24px;">

        <div style="text-align:center;margin-bottom:32px;">
          <div style="font-size:11px;letter-spacing:0.2em;text-transform:uppercase;color:#00D4F5;margin-bottom:8px;">CFL Water Treatment</div>
          <h1 style="font-size:28px;color:#F4F8FF;margin:0 0 8px;">Water Quality Proposal</h1>
          <div style="font-size:13px;color:rgba(190,220,250,0.5);">${date}</div>
        </div>

        <div style="background:rgba(11,22,40,0.92);border:1px solid rgba(0,196,232,0.15);border-radius:14px;padding:24px;margin-bottom:20px;">
          <div style="font-size:11px;letter-spacing:0.15em;text-transform:uppercase;color:#00D4F5;margin-bottom:16px;">Customer Information</div>
          <table style="width:100%;border-collapse:collapse;">
            <tr><td style="padding:4px 0;color:rgba(190,220,250,0.6);width:120px;">Name</td><td style="padding:4px 0;color:#F4F8FF;">${name}</td></tr>
            <tr><td style="padding:4px 0;color:rgba(190,220,250,0.6);">Address</td><td style="padding:4px 0;color:#F4F8FF;">${address || '—'}</td></tr>
            <tr><td style="padding:4px 0;color:rgba(190,220,250,0.6);">Email</td><td style="padding:4px 0;color:#F4F8FF;">${email || '—'}</td></tr>
            <tr><td style="padding:4px 0;color:rgba(190,220,250,0.6);">Phone</td><td style="padding:4px 0;color:#F4F8FF;">${phone || '—'}</td></tr>
            <tr><td style="padding:4px 0;color:rgba(190,220,250,0.6);">Water Source</td><td style="padding:4px 0;color:#F4F8FF;">${waterSource || '—'}</td></tr>
          </table>
        </div>

        <div style="background:rgba(11,22,40,0.92);border:1px solid rgba(201,168,76,0.30);border-radius:14px;padding:24px;margin-bottom:20px;">
          <div style="font-size:11px;letter-spacing:0.15em;text-transform:uppercase;color:#D4B458;margin-bottom:16px;">Hard Water Cost Assessment</div>
          <div style="text-align:center;margin-bottom:20px;">
            <div style="font-size:42px;font-weight:700;color:#D4B458;">$${annual}</div>
            <div style="font-size:13px;color:rgba(190,220,250,0.5);">Estimated annual cost of untreated water</div>
            <div style="font-size:14px;color:rgba(190,220,250,0.7);margin-top:8px;">Over 10 years: <strong style="color:#F4F8FF;">$${lifetimeCost}</strong></div>
          </div>
          ${sliderRows ? `
          <table style="width:100%;border-collapse:collapse;">
            ${sliderRows}
          </table>` : ''}
        </div>

        <div style="text-align:center;padding:24px;background:rgba(0,196,232,0.06);border:1px solid rgba(0,196,232,0.15);border-radius:14px;">
          <div style="font-size:13px;color:rgba(190,220,250,0.6);margin-bottom:8px;">Ready to eliminate these costs?</div>
          <div style="font-size:18px;color:#F4F8FF;font-weight:600;">Call CFL Water Treatment</div>
          <div style="font-size:22px;color:#00D4F5;font-weight:700;margin-top:4px;">386-349-0533</div>
        </div>

      </div>
    </body>
    </html>
  `;

  /* Also fire notification email */
  try {
    const transporter = getTransporter();
    await transporter.sendMail({
      from:    `"The Water App" <${process.env.GMAIL_USER}>`,
      to:      process.env.NOTIFY_EMAIL,
      replyTo: email || process.env.NOTIFY_EMAIL,
      subject: `💧 New Proposal — ${name} | $${annual}/yr`,
      html:    proposalHtml
    });
  } catch (emailErr) {
    console.error('Proposal email error:', emailErr.message);
    // Don't fail the request just because email errored
  }

  res.json({ success: true, proposalHtml });
});

/* ─── Start ─────────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`Water App Relay running on port ${PORT}`);
});
