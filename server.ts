import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import dotenv from 'dotenv';
import express from 'express';
import type {NextFunction, Request, Response} from 'express';
import QRCode from 'qrcode';
import {
  INITIAL_BOOKINGS,
  INITIAL_PACKAGES,
  INITIAL_REVIEWS,
  INITIAL_SETTINGS,
  buildInitialTests,
} from './server/seedData.ts';
import type {
  BookingItem,
  BookingRecord,
  BookingStatus,
  DepartmentType,
  HealthPackage,
  LabSettings,
  LabTest,
  PaymentStatus,
  ReportParameter,
  ReviewRecord,
} from './src/types.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'alhayat-db.json');

interface AdminAuthState {
  username: string;
  allowedIdentifiers: string[];
  passwordSalt: string;
  passwordHash: string;
  mustChangePassword: boolean;
  passwordUpdatedAt: string | null;
}

interface DatabaseSchema {
  adminAuth: AdminAuthState;
  settings: LabSettings;
  tests: LabTest[];
  packages: HealthPackage[];
  bookings: BookingRecord[];
  reviews: ReviewRecord[];
  nextBookingSeq: number;
}

interface AdminSession {
  token: string;
  createdAt: number;
  expiresAt: number;
}

const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const sessions = new Map<string, AdminSession>();
const loginAttempts = new Map<string, {count: number; resetAt: number}>();

function hashPassword(password: string, saltHex?: string): {salt: string; hash: string} {
  const salt = saltHex || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return {salt, hash};
}

function verifyPassword(password: string, saltHex: string, expectedHashHex: string): boolean {
  const derived = crypto.scryptSync(password, saltHex, 64);
  const expected = Buffer.from(expectedHashHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

function loadOrCreateDatabase(): DatabaseSchema {
  fs.mkdirSync(DATA_DIR, {recursive: true});

  if (fs.existsSync(DB_PATH)) {
    try {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      const parsed = JSON.parse(raw) as DatabaseSchema;
      if (parsed && parsed.adminAuth && Array.isArray(parsed.tests)) {
        return parsed;
      }
    } catch (err) {
      console.error('Failed to parse existing DB, recreating:', err);
    }
  }

  // Server-side temporary bootstrap credential ONLY — never exposed to client code.
  // Admin MUST change this password on first login before accessing any portal data.
  const initialTempPassword = process.env.ADMIN_INITIAL_PASSWORD?.trim() || '123123';
  const {salt, hash} = hashPassword(initialTempPassword);

  const initialDb: DatabaseSchema = {
    adminAuth: {
      username: 'admin',
      allowedIdentifiers: [
        'admin',
        'toseef',
        'toseefgulistan',
        '03420806062',
        '0342-0806062',
        'toseefgulistan6@gmail.com',
      ],
      passwordSalt: salt,
      passwordHash: hash,
      mustChangePassword: true,
      passwordUpdatedAt: null,
    },
    settings: INITIAL_SETTINGS,
    tests: buildInitialTests(),
    packages: INITIAL_PACKAGES,
    bookings: INITIAL_BOOKINGS,
    reviews: INITIAL_REVIEWS,
    nextBookingSeq: 1003,
  };

  saveDatabase(initialDb);
  return initialDb;
}

function saveDatabase(data: DatabaseSchema): void {
  fs.mkdirSync(DATA_DIR, {recursive: true});
  const tmpPath = `${DB_PATH}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmpPath, DB_PATH);
}

const db = loadOrCreateDatabase();
const BASE_SEED_TESTS: LabTest[] = buildInitialTests();

interface FirebaseAppletConfig {
  projectId: string;
  apiKey: string;
  firestoreDatabaseId: string;
}

function loadFirebaseAppletConfig(): FirebaseAppletConfig | null {
  try {
    const cfgPath = path.join(__dirname, 'firebase-applet-config.json');
    if (!fs.existsSync(cfgPath)) return null;
    const parsed = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as Partial<FirebaseAppletConfig>;
    if (parsed.projectId && parsed.apiKey && parsed.firestoreDatabaseId) {
      return {
        projectId: parsed.projectId,
        apiKey: parsed.apiKey,
        firestoreDatabaseId: parsed.firestoreDatabaseId,
      };
    }
  } catch (err) {
    console.error('Unable to load firebase-applet-config.json:', err);
  }
  return null;
}

const fbAppletConfig = loadFirebaseAppletConfig();
const BOOTSTRAPPED_OWNER_EMAIL = 'toseefgulistan6@gmail.com';

// Server-Sent Events (SSE) real-time broadcast clients
const sseClients = new Set<Response>();

function broadcastSync(reason: string): void {
  const payload = JSON.stringify({type: 'sync', reason, ts: Date.now()});
  for (const client of sseClients) {
    try {
      client.write(`data: ${payload}\n\n`);
    } catch {
      sseClients.delete(client);
    }
  }
}

function fromFirestoreValue(val: Record<string, unknown> | undefined): unknown {
  if (!val || typeof val !== 'object') return undefined;
  if ('stringValue' in val) return String(val.stringValue);
  if ('integerValue' in val) return Number(val.integerValue);
  if ('doubleValue' in val) return Number(val.doubleValue);
  if ('booleanValue' in val) return Boolean(val.booleanValue);
  if ('nullValue' in val) return null;
  if ('timestampValue' in val) return String(val.timestampValue);
  if ('arrayValue' in val) {
    const arr = (val.arrayValue as {values?: Array<Record<string, unknown>>})?.values || [];
    return arr.map((item) => fromFirestoreValue(item));
  }
  if ('mapValue' in val) {
    const fields =
      (val.mapValue as {fields?: Record<string, Record<string, unknown>>})?.fields || {};
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(fields)) {
      out[k] = fromFirestoreValue(v);
    }
    return out;
  }
  return undefined;
}

function parseFirestoreFields(
  fields: Record<string, Record<string, unknown>> | undefined
): Record<string, unknown> {
  if (!fields) return {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(fields)) {
    out[k] = fromFirestoreValue(v);
  }
  return out;
}

let lastCloudCheckAt = 0;
let lastAppliedCloudSettingsMs = 0;
let lastAppliedCloudCatalogMs = 0;

async function syncLocalDbFromCloudFirestore(force = false): Promise<void> {
  if (!fbAppletConfig) return;
  const now = Date.now();
  if (!force && now - lastCloudCheckAt < 3000) return;
  lastCloudCheckAt = now;

  const baseDocUrl = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(
    fbAppletConfig.projectId
  )}/databases/${encodeURIComponent(fbAppletConfig.firestoreDatabaseId)}/documents`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2500);

  let mutated = false;
  try {
    const [settingsResp, catalogResp] = await Promise.all([
      fetch(`${baseDocUrl}/settings/live?key=${encodeURIComponent(fbAppletConfig.apiKey)}`, {
        signal: controller.signal,
      }),
      fetch(`${baseDocUrl}/catalog_state/live?key=${encodeURIComponent(fbAppletConfig.apiKey)}`, {
        signal: controller.signal,
      }),
    ]);

    if (settingsResp.ok) {
      const sJson = (await settingsResp.json()) as {
        fields?: Record<string, Record<string, unknown>>;
        updateTime?: string;
      };
      const updateMs = sJson.updateTime ? Date.parse(sJson.updateTime) : 0;
      if (force || updateMs > lastAppliedCloudSettingsMs) {
        const d = parseFirestoreFields(sJson.fields);
        if (d.labName) {
          db.settings = {
            ...db.settings,
            labName: String(d.labName || db.settings.labName),
            labNameUr: String(d.labNameUr || db.settings.labNameUr),
            subtitle: String(d.subtitle || db.settings.subtitle),
            subtitleUr: String(d.subtitleUr || db.settings.subtitleUr),
            tagline: String(d.tagline || db.settings.tagline),
            taglineUr: String(d.taglineUr || db.settings.taglineUr),
            managingDirector: String(d.managingDirector || db.settings.managingDirector),
            managingDirectorUr: String(d.managingDirectorUr || db.settings.managingDirectorUr),
            primaryPhone: String(d.primaryPhone || db.settings.primaryPhone),
            secondaryPhone: String(d.secondaryPhone || db.settings.secondaryPhone),
            whatsappNumber: String(d.whatsappNumber || db.settings.whatsappNumber),
            address: String(d.address || db.settings.address),
            addressUr: String(d.addressUr || db.settings.addressUr),
            timings: String(d.timings || db.settings.timings),
            timingsUr: String(d.timingsUr || db.settings.timingsUr),
            specialNoticeEn: String(d.specialNoticeEn || db.settings.specialNoticeEn),
            specialNoticeUr: String(d.specialNoticeUr || db.settings.specialNoticeUr),
            homeCollectionFee: Number(d.homeCollectionFee ?? db.settings.homeCollectionFee),
            freeHomeCollectionThreshold: Number(
              d.freeHomeCollectionThreshold ?? db.settings.freeHomeCollectionThreshold
            ),
            publicWebsiteUrl: d.publicWebsiteUrl ? String(d.publicWebsiteUrl) : undefined,
          };
          if (updateMs > 0) lastAppliedCloudSettingsMs = updateMs;
          mutated = true;
        }
      }
    }

    if (catalogResp.ok) {
      const cJson = (await catalogResp.json()) as {
        fields?: Record<string, Record<string, unknown>>;
        updateTime?: string;
      };
      const updateMs = cJson.updateTime ? Date.parse(cJson.updateTime) : 0;
      if (force || updateMs > lastAppliedCloudCatalogMs) {
        const d = parseFirestoreFields(cJson.fields);
        const priceOverrides = (d.priceOverrides as Record<string, number>) || {};
        const flagOverrides =
          (d.flagOverrides as Record<string, {active: boolean; popular: boolean}>) || {};
        const customTests = (d.customTests as Record<string, LabTest>) || {};
        const deletedTestIds = (d.deletedTestIds as Record<string, boolean>) || {};
        const packagesMap = (d.packagesMap as Record<string, HealthPackage>) || {};
        const reviewsMap = (d.reviewsMap as Record<string, ReviewRecord>) || {};

        const mergedSeed = BASE_SEED_TESTS.filter((t) => !deletedTestIds[t.id]).map((t) => {
          const customPatch = customTests[t.id];
          const flagPatch = flagOverrides[t.id];
          const nextPrice =
            priceOverrides[t.id] !== undefined ? Number(priceOverrides[t.id]) : t.price;
          return {
            ...t,
            ...(customPatch || {}),
            price: Number.isFinite(nextPrice) ? nextPrice : t.price,
            active: flagPatch
              ? Boolean(flagPatch.active)
              : customPatch
              ? Boolean(customPatch.active)
              : t.active,
            popular: flagPatch
              ? Boolean(flagPatch.popular)
              : customPatch
              ? Boolean(customPatch.popular)
              : t.popular,
          };
        });

        const seedIdSet = new Set(BASE_SEED_TESTS.map((t) => t.id));
        const extraTests = Object.values(customTests).filter(
          (ct) => ct && ct.id && !seedIdSet.has(ct.id) && !deletedTestIds[ct.id]
        );
        db.tests = [...extraTests, ...mergedSeed];

        const cloudPkgs = Object.values(packagesMap).filter((p) => p && p.id);
        if (cloudPkgs.length > 0) {
          db.packages = cloudPkgs;
        }

        const cloudRevs = Object.values(reviewsMap).filter((r) => r && r.id);
        if (cloudRevs.length > 0) {
          const byId = new Map<string, ReviewRecord>();
          for (const r of cloudRevs) byId.set(r.id, r);
          for (const localRev of db.reviews) {
            if (!byId.has(localRev.id)) byId.set(localRev.id, localRev);
          }
          db.reviews = Array.from(byId.values()).sort((a, b) =>
            (b.createdAt || '').localeCompare(a.createdAt || '')
          );
        }

        if (updateMs > 0) lastAppliedCloudCatalogMs = updateMs;
        mutated = true;
      }
    }

    if (mutated) {
      saveDatabase(db);
    }
  } catch {
    // Graceful fallback if cloud endpoint unreachable
  } finally {
    clearTimeout(timeout);
  }
}

function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    const parts = cookieHeader.split(';');
    for (const part of parts) {
      const [k, v] = part.trim().split('=');
      if (k === 'ahl_admin_session' && v) {
        return decodeURIComponent(v);
      }
    }
  }
  return null;
}

function getValidSession(req: Request): AdminSession | null {
  const token = extractToken(req);
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function requireAdminAuth(req: Request, res: Response, next: NextFunction): void {
  const session = getValidSession(req);
  if (!session) {
    res.status(401).json({error: 'UNAUTHORIZED', message: 'Admin authentication required.'});
    return;
  }
  next();
}

function requireAdminReady(req: Request, res: Response, next: NextFunction): void {
  const session = getValidSession(req);
  if (!session) {
    res.status(401).json({error: 'UNAUTHORIZED', message: 'Admin authentication required.'});
    return;
  }
  if (db.adminAuth.mustChangePassword) {
    res.status(403).json({
      error: 'PASSWORD_CHANGE_REQUIRED',
      message: 'Security policy requires changing the temporary password on first login.',
    });
    return;
  }
  next();
}

function normalizePhone(phone: string): string {
  return phone.replace(/[^0-9]/g, '');
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({limit: '10mb'}));

  // Security headers
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // ============================================================================
  // LIVE SSE STREAM & CLOUD SYNC NOTIFICATION
  // ============================================================================

  app.get('/api/events', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    res.write(`data: ${JSON.stringify({type: 'connected', ts: Date.now()})}\n\n`);
    sseClients.add(res);

    const keepAlive = setInterval(() => {
      try {
        res.write(': keepalive\n\n');
      } catch {
        clearInterval(keepAlive);
        sseClients.delete(res);
      }
    }, 25000);

    req.on('close', () => {
      clearInterval(keepAlive);
      sseClients.delete(res);
    });
  });

  app.post('/api/sync-notify', async (_req, res) => {
    await syncLocalDbFromCloudFirestore(true);
    broadcastSync('cloud-sync');
    res.json({ok: true});
  });

  // ============================================================================
  // PUBLIC PATIENT & CATALOG API
  // ============================================================================

  app.get('/api/bootstrap', async (_req, res) => {
    await syncLocalDbFromCloudFirestore();
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      settings: db.settings,
      tests: db.tests.filter((t) => t.active),
      packages: db.packages.filter((p) => p.active),
      reviews: db.reviews.filter((r) => r.approved),
    });
  });

  // Reliable Server-Side QR PNG Attachment Download
  app.get('/api/download/qr-png', async (req, res) => {
    try {
      const rawUrl = String(req.query.url || '').trim();
      const rawName = String(req.query.filename || 'Al-Hayat-Lab-Website-QR.png')
        .replace(/[^a-zA-Z0-9._-]/g, '-')
        .replace(/-+/g, '-');
      const safeFilename = rawName.endsWith('.png') ? rawName : `${rawName}.png`;
      const targetUrl =
        rawUrl.startsWith('http://') || rawUrl.startsWith('https://')
          ? rawUrl
          : db.settings.publicWebsiteUrl || process.env.SHARED_APP_URL || process.env.APP_URL || 'https://ais-pre-iuvcwpourp4bl4i3mpguen-769253255547.asia-northeast1.run.app';

      const pngBuffer = await QRCode.toBuffer(targetUrl, {
        type: 'png',
        width: 640,
        margin: 2,
        color: {
          dark: '#1E297B',
          light: '#FFFFFF',
        },
      });

      res.setHeader('Content-Type', 'image/png');
      res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
      res.setHeader('Content-Length', String(pngBuffer.length));
      res.send(pngBuffer);
    } catch {
      res.status(500).json({error: 'QR_ERROR', message: 'Unable to generate QR PNG.'});
    }
  });

  // Save Desktop / Phone Chrome Shortcut Launcher (.html file that opens live website in Chrome)
  app.get('/api/download/shortcut', (req, res) => {
    const mode = req.query.mode === 'admin' ? 'admin' : 'website';
    const rawBase = String(req.query.url || '').trim();
    const baseUrl = (
      rawBase.startsWith('http://') || rawBase.startsWith('https://')
        ? rawBase
        : db.settings.publicWebsiteUrl ||
          process.env.SHARED_APP_URL ||
          process.env.APP_URL ||
          'https://ais-pre-iuvcwpourp4bl4i3mpguen-769253255547.asia-northeast1.run.app'
    ).replace(/\/+$/, '');

    const targetHref = mode === 'admin' ? `${baseUrl}/#admin` : baseUrl;
    const filename =
      mode === 'admin'
        ? 'Al-Hayat-Lab-Owner-Entry-Shortcut.html'
        : 'Al-Hayat-Lab-Mirpur-Website-Shortcut.html';
    const titleText =
      mode === 'admin'
        ? 'Al-Hayat Lab — Skin Care Center (Online Admin & Entry Portal)'
        : 'Al-Hayat Lab — Skin Care Center (Official Online Website)';

    const shortcutHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${titleText}</title>
  <meta http-equiv="refresh" content="0; url=${targetHref}" />
  <script>window.location.replace(${JSON.stringify(targetHref)});</script>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #f8fafc; color: #0f172a; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 24px; }
    .box { max-width: 480px; width: 100%; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 12px; padding: 28px; text-align: center; }
    .brand { font-size: 20px; font-weight: 800; color: #26318c; margin: 0; letter-spacing: -0.01em; }
    .sub { font-size: 13px; font-weight: 700; color: #dc2626; margin: 4px 0 12px; }
    p { font-size: 13px; color: #475569; margin: 0 0 18px; line-height: 1.5; }
    a.btn { display: inline-block; background: #26318c; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 8px; font-size: 13px; font-weight: 600; }
    .url { margin-top: 14px; font-family: monospace; font-size: 11px; color: #1e297b; background: #f1f5f9; padding: 8px 10px; border-radius: 6px; word-break: break-all; }
  </style>
</head>
<body>
  <div class="box">
    <p class="brand">AL-HAYAT LAB</p>
    <p class="sub">Skin Care Center &amp; Laboratory — Mirpur</p>
    <p>Opening online in Google Chrome...</p>
    <a class="btn" href="${targetHref}">Open in Google Chrome</a>
    <div class="url">${targetHref}</div>
  </div>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(shortcutHtml);
  });

  // Create Online Patient Booking
  app.post('/api/bookings', async (req, res) => {
    await syncLocalDbFromCloudFirestore();
    const {
      patientName,
      patientPhone,
      patientAge,
      patientGender,
      collectionType,
      address,
      preferredDate,
      preferredTime,
      doctorRef,
      notes,
      itemIds,
      prescriptionImage,
      prescriptionFileName,
    } = req.body as {
      patientName?: string;
      patientPhone?: string;
      patientAge?: string;
      patientGender?: 'Male' | 'Female' | 'Other';
      collectionType?: 'lab_visit' | 'home_collection';
      address?: string;
      preferredDate?: string;
      preferredTime?: string;
      doctorRef?: string;
      notes?: string;
      itemIds?: Array<{id: string; type: 'test' | 'package'}>;
      prescriptionImage?: string;
      prescriptionFileName?: string;
    };

    const hasItems = Array.isArray(itemIds) && itemIds.length > 0;
    const hasPrescription = Boolean(prescriptionImage && prescriptionImage.trim().length > 0);

    if (!patientName?.trim() || !patientPhone?.trim() || (!hasItems && !hasPrescription)) {
      res.status(400).json({
        error: 'VALIDATION_ERROR',
        message:
          'Patient name, phone number, and either selected tests or an uploaded prescription are required.',
      });
      return;
    }

    if (collectionType === 'home_collection' && !address?.trim()) {
      res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'Complete residential address in Mirpur is required for Home Sample Collection.',
      });
      return;
    }

    const resolvedItems: BookingItem[] = [];
    let hasFreeHomePkg = false;

    if (Array.isArray(itemIds)) {
      for (const entry of itemIds) {
        if (entry.type === 'package') {
          const pkg = db.packages.find((p) => p.id === entry.id && p.active);
          if (pkg) {
            if (pkg.homeCollectionFree) hasFreeHomePkg = true;
            resolvedItems.push({
              id: pkg.id,
              type: 'package',
              code: pkg.code,
              name: pkg.name,
              turnaround: pkg.turnaround,
              price: pkg.packagePrice,
            });
          }
        } else {
          const test = db.tests.find((t) => t.id === entry.id && t.active);
          if (test) {
            resolvedItems.push({
              id: test.id,
              type: 'test',
              code: test.code,
              name: test.name,
              department: test.department,
              turnaround: test.turnaround,
              price: test.price,
            });
          }
        }
      }
    }

    if (resolvedItems.length === 0 && hasPrescription) {
      resolvedItems.push({
        id: 'rx-upload',
        type: 'test',
        code: 'RX-SLIP',
        name: 'Tests as per Uploaded Doctor Prescription / Slip',
        department: 'Clinical Pathology',
        turnaround: 'As per Lab Review',
        price: 0,
      });
    }

    if (resolvedItems.length === 0) {
      res.status(400).json({error: 'INVALID_ITEMS', message: 'Selected tests or packages were not found.'});
      return;
    }

    const subtotal = resolvedItems.reduce((sum, item) => sum + item.price, 0);
    const isHome = collectionType === 'home_collection';
    const homeCollectionFee =
      isHome && !hasFreeHomePkg && (subtotal === 0 || subtotal < db.settings.freeHomeCollectionThreshold)
        ? db.settings.homeCollectionFee
        : 0;
    const totalAmount = subtotal + homeCollectionFee;

    const seq = db.nextBookingSeq++;
    const bookingId = `AHL-2026-${seq}`;
    const verificationPin = String(crypto.randomInt(1000, 9999));
    const now = new Date().toISOString();

    const cleanAddress = (address || '').trim() || (isHome ? 'Mirpur AJK' : db.settings.address);

    const newBooking: BookingRecord = {
      id: bookingId,
      verificationPin,
      patientName: patientName.trim(),
      patientPhone: patientPhone.trim(),
      patientAge: (patientAge || '').trim() || 'N/A',
      patientGender: patientGender || 'Male',
      collectionType: isHome ? 'home_collection' : 'lab_visit',
      address: cleanAddress,
      preferredDate: preferredDate || now.slice(0, 10),
      preferredTime: preferredTime || '10:00 AM',
      doctorRef: (doctorRef || '').trim() || 'Self / Walk-in',
      notes: (notes || '').trim(),
      items: resolvedItems,
      subtotal,
      homeCollectionFee,
      discount: 0,
      totalAmount,
      paymentStatus: 'Unpaid',
      status: 'Pending',
      createdAt: now,
      updatedAt: now,
      reportPublished: false,
      reportResults: [],
      prescriptionImage: hasPrescription ? prescriptionImage : undefined,
      prescriptionFileName: hasPrescription ? (prescriptionFileName || 'prescription.jpg') : undefined,
    };

    db.bookings.unshift(newBooking);
    saveDatabase(db);
    broadcastSync('booking-created');
    res.status(201).json({booking: newBooking});
  });

  // Patient Portal Lookup (by Booking ID or Phone Number)
  app.get('/api/patient/lookup', (req, res) => {
    const rawQuery = String(req.query.query || '').trim();
    if (!rawQuery) {
      res.status(400).json({error: 'QUERY_REQUIRED', message: 'Please enter a Booking ID or Phone Number.'});
      return;
    }

    const upperQuery = rawQuery.toUpperCase();
    const digitsQuery = normalizePhone(rawQuery);

    const matches = db.bookings.filter((b) => {
      if (b.id.toUpperCase() === upperQuery) return true;
      const bDigits = normalizePhone(b.patientPhone);
      if (digitsQuery.length >= 7 && bDigits.endsWith(digitsQuery.slice(-9))) return true;
      return false;
    });

    res.json({bookings: matches});
  });

  // Submit Patient Review
  app.post('/api/reviews', (req, res) => {
    const {patientName, location, serviceUsed, rating, comment, bookingId} = req.body as {
      patientName?: string;
      location?: string;
      serviceUsed?: string;
      rating?: number;
      comment?: string;
      bookingId?: string;
    };

    if (!patientName?.trim() || !comment?.trim() || !rating) {
      res.status(400).json({error: 'VALIDATION_ERROR', message: 'Name, rating, and feedback are required.'});
      return;
    }

    const cleanBookingId = (bookingId || '').trim().toUpperCase();
    const matchedBooking = cleanBookingId
      ? db.bookings.find((b) => b.id.toUpperCase() === cleanBookingId)
      : undefined;

    const newReview: ReviewRecord = {
      id: `rev-${Date.now()}`,
      patientName: patientName.trim(),
      location: (location || 'Mirpur AJK').trim(),
      serviceUsed: (serviceUsed || 'Diagnostic Lab Service').trim(),
      rating: Math.min(5, Math.max(1, Number(rating) || 5)),
      comment: comment.trim(),
      bookingId: cleanBookingId || undefined,
      verifiedPatient: Boolean(matchedBooking),
      approved: true,
      createdAt: new Date().toISOString(),
    };

    db.reviews.unshift(newReview);
    saveDatabase(db);
    broadcastSync('review-created');
    res.status(201).json({review: newReview});
  });

  // ============================================================================
  // SECURE ADMIN AUTHENTICATION & MANDATORY FIRST-LOGIN PASSWORD CHANGE
  // ============================================================================

  app.get('/api/admin/session', (req, res) => {
    const session = getValidSession(req);
    if (!session) {
      res.json({authenticated: false, mustChangePassword: false});
      return;
    }
    res.json({
      authenticated: true,
      mustChangePassword: db.adminAuth.mustChangePassword,
      adminUser: 'M.D Toseef Gulistan',
      passwordUpdatedAt: db.adminAuth.passwordUpdatedAt,
    });
  });

  app.post('/api/admin/login', (req, res) => {
    const clientKey = req.ip || 'local';
    const now = Date.now();
    const attempt = loginAttempts.get(clientKey);
    if (attempt && now < attempt.resetAt && attempt.count >= 6) {
      const waitSecs = Math.ceil((attempt.resetAt - now) / 1000);
      res.status(429).json({
        error: 'RATE_LIMITED',
        message: `Too many failed login attempts. Please wait ${waitSecs} seconds.`,
      });
      return;
    }

    const {username, password} = req.body as {username?: string; password?: string};
    const cleanUser = (username || 'admin').trim().toLowerCase();
    const cleanPass = String(password || '');

    const userValid = db.adminAuth.allowedIdentifiers.some(
      (id) => id.toLowerCase() === cleanUser
    );
    const passValid =
      cleanPass.length > 0 &&
      verifyPassword(cleanPass, db.adminAuth.passwordSalt, db.adminAuth.passwordHash);

    if (!userValid || !passValid) {
      const prev = attempt && now < attempt.resetAt ? attempt.count : 0;
      loginAttempts.set(clientKey, {count: prev + 1, resetAt: now + 10 * 60 * 1000});
      res.status(401).json({
        error: 'INVALID_CREDENTIALS',
        message: 'Invalid administrator username or password.',
      });
      return;
    }

    loginAttempts.delete(clientKey);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, {
      token,
      createdAt: now,
      expiresAt: now + SESSION_TTL_MS,
    });

    res.setHeader(
      'Set-Cookie',
      `ahl_admin_session=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${
        SESSION_TTL_MS / 1000
      }; SameSite=Lax`
    );

    res.json({
      authenticated: true,
      token,
      mustChangePassword: db.adminAuth.mustChangePassword,
      adminUser: 'M.D Toseef Gulistan',
    });
  });

  // Verified Google Cloud Owner Login (toseefgulistan6@gmail.com)
  app.post('/api/admin/google-login', async (req, res) => {
    const {idToken} = req.body as {idToken?: string};
    if (!idToken || !fbAppletConfig?.apiKey) {
      res.status(400).json({error: 'MISSING_TOKEN', message: 'Google ID token is required.'});
      return;
    }

    try {
      const verifyResp = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(
          fbAppletConfig.apiKey
        )}`,
        {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({idToken}),
        }
      );

      if (!verifyResp.ok) {
        res.status(401).json({error: 'INVALID_TOKEN', message: 'Google token verification failed.'});
        return;
      }

      const payload = (await verifyResp.json()) as {
        users?: Array<{email?: string; emailVerified?: boolean}>;
      };
      const account = payload.users?.[0];
      if (
        !account ||
        !account.emailVerified ||
        account.email?.toLowerCase() !== BOOTSTRAPPED_OWNER_EMAIL
      ) {
        res.status(403).json({
          error: 'FORBIDDEN_EMAIL',
          message: `Only verified owner (${BOOTSTRAPPED_OWNER_EMAIL}) can unlock Admin via Google.`,
        });
        return;
      }

      if (db.adminAuth.mustChangePassword) {
        db.adminAuth.mustChangePassword = false;
        db.adminAuth.passwordUpdatedAt = new Date().toISOString();
        saveDatabase(db);
      }

      const now = Date.now();
      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, {
        token,
        createdAt: now,
        expiresAt: now + SESSION_TTL_MS,
      });

      res.setHeader(
        'Set-Cookie',
        `ahl_admin_session=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${
          SESSION_TTL_MS / 1000
        }; SameSite=Lax`
      );

      res.json({
        authenticated: true,
        token,
        mustChangePassword: false,
        adminUser: 'M.D Toseef Gulistan',
      });
    } catch {
      res.status(500).json({error: 'AUTH_ERROR', message: 'Unable to verify Google owner session.'});
    }
  });

  app.post('/api/admin/logout', (req, res) => {
    const token = extractToken(req);
    if (token) sessions.delete(token);
    res.setHeader('Set-Cookie', 'ahl_admin_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
    res.json({ok: true});
  });

  app.post('/api/admin/change-password', requireAdminAuth, (req, res) => {
    const {currentPassword, newPassword} = req.body as {
      currentPassword?: string;
      newPassword?: string;
    };

    if (!currentPassword || !newPassword) {
      res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'Current password and new password are required.',
      });
      return;
    }

    const currentValid = verifyPassword(
      currentPassword,
      db.adminAuth.passwordSalt,
      db.adminAuth.passwordHash
    );
    if (!currentValid) {
      res.status(401).json({
        error: 'INVALID_CURRENT_PASSWORD',
        message: 'The current password you entered is incorrect.',
      });
      return;
    }

    const trimmedNew = newPassword.trim();
    if (trimmedNew.length < 8) {
      res.status(400).json({
        error: 'WEAK_PASSWORD',
        message: 'New password must be at least 8 characters long.',
      });
      return;
    }

    if (
      trimmedNew === '123123' ||
      verifyPassword(trimmedNew, db.adminAuth.passwordSalt, db.adminAuth.passwordHash)
    ) {
      res.status(400).json({
        error: 'PASSWORD_REUSE',
        message: 'New password must be different from the temporary/current password.',
      });
      return;
    }

    const {salt, hash} = hashPassword(trimmedNew);
    db.adminAuth.passwordSalt = salt;
    db.adminAuth.passwordHash = hash;
    db.adminAuth.mustChangePassword = false;
    db.adminAuth.passwordUpdatedAt = new Date().toISOString();
    saveDatabase(db);

    res.json({
      ok: true,
      mustChangePassword: false,
      passwordUpdatedAt: db.adminAuth.passwordUpdatedAt,
    });
  });

  // ============================================================================
  // PROTECTED ADMIN PORTAL MANAGEMENT ROUTES (Requires Password Changed!)
  // ============================================================================

  app.get('/api/admin/overview', requireAdminReady, async (_req, res) => {
    await syncLocalDbFromCloudFirestore();
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      settings: db.settings,
      tests: db.tests,
      baseTests: BASE_SEED_TESTS,
      packages: db.packages,
      bookings: db.bookings,
      reviews: db.reviews,
    });
  });

  // Admin Walk-in / Desk Invoice Creator
  app.post('/api/admin/bookings', requireAdminReady, (req, res) => {
    const {
      patientName,
      patientPhone,
      patientAge,
      patientGender,
      collectionType,
      address,
      doctorRef,
      notes,
      discount,
      paymentStatus,
      status,
      itemIds,
    } = req.body as {
      patientName?: string;
      patientPhone?: string;
      patientAge?: string;
      patientGender?: 'Male' | 'Female' | 'Other';
      collectionType?: 'lab_visit' | 'home_collection';
      address?: string;
      doctorRef?: string;
      notes?: string;
      discount?: number;
      paymentStatus?: PaymentStatus;
      status?: BookingStatus;
      itemIds?: Array<{id: string; type: 'test' | 'package'}>;
    };

    if (!patientName?.trim() || !patientPhone?.trim() || !Array.isArray(itemIds) || itemIds.length === 0) {
      res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'Patient name, phone, and at least one test/package are required.',
      });
      return;
    }

    const resolvedItems: BookingItem[] = [];
    for (const entry of itemIds) {
      if (entry.type === 'package') {
        const pkg = db.packages.find((p) => p.id === entry.id);
        if (pkg) {
          resolvedItems.push({
            id: pkg.id,
            type: 'package',
            code: pkg.code,
            name: pkg.name,
            turnaround: pkg.turnaround,
            price: pkg.packagePrice,
          });
        }
      } else {
        const test = db.tests.find((t) => t.id === entry.id);
        if (test) {
          resolvedItems.push({
            id: test.id,
            type: 'test',
            code: test.code,
            name: test.name,
            department: test.department,
            turnaround: test.turnaround,
            price: test.price,
          });
        }
      }
    }

    const subtotal = resolvedItems.reduce((s, i) => s + i.price, 0);
    const isHome = collectionType === 'home_collection';
    const homeCollectionFee = isHome ? db.settings.homeCollectionFee : 0;
    const cleanDiscount = Math.max(0, Math.min(subtotal + homeCollectionFee, Number(discount) || 0));
    const totalAmount = Math.max(0, subtotal + homeCollectionFee - cleanDiscount);

    const seq = db.nextBookingSeq++;
    const now = new Date().toISOString();

    const booking: BookingRecord = {
      id: `AHL-2026-${seq}`,
      verificationPin: String(crypto.randomInt(1000, 9999)),
      patientName: patientName.trim(),
      patientPhone: patientPhone.trim(),
      patientAge: (patientAge || '').trim() || 'N/A',
      patientGender: patientGender || 'Male',
      collectionType: isHome ? 'home_collection' : 'lab_visit',
      address: isHome ? (address || 'Mirpur AJK').trim() : db.settings.address,
      preferredDate: now.slice(0, 10),
      preferredTime: new Date().toLocaleTimeString('en-US', {hour: '2-digit', minute: '2-digit'}),
      doctorRef: (doctorRef || 'Walk-in / Reception').trim(),
      notes: (notes || '').trim(),
      items: resolvedItems,
      subtotal,
      homeCollectionFee,
      discount: cleanDiscount,
      totalAmount,
      paymentStatus: paymentStatus || 'Paid',
      status: status || 'Sample Collected',
      createdAt: now,
      updatedAt: now,
      reportPublished: false,
      reportResults: [],
    };

    db.bookings.unshift(booking);
    saveDatabase(db);
    broadcastSync('admin-booking-created');
    res.status(201).json({booking});
  });

  app.patch('/api/admin/bookings/:id', requireAdminReady, (req, res) => {
    const booking = db.bookings.find((b) => b.id === req.params.id);
    if (!booking) {
      res.status(404).json({error: 'NOT_FOUND', message: 'Booking not found.'});
      return;
    }

    const {status, paymentStatus, discount, doctorRef, notes} = req.body as {
      status?: BookingStatus;
      paymentStatus?: PaymentStatus;
      discount?: number;
      doctorRef?: string;
      notes?: string;
    };

    if (status) booking.status = status;
    if (paymentStatus) booking.paymentStatus = paymentStatus;
    if (discount !== undefined) {
      booking.discount = Math.max(0, Number(discount) || 0);
      booking.totalAmount = Math.max(0, booking.subtotal + booking.homeCollectionFee - booking.discount);
    }
    if (doctorRef !== undefined) booking.doctorRef = doctorRef;
    if (notes !== undefined) booking.notes = notes;
    booking.updatedAt = new Date().toISOString();

    saveDatabase(db);
    broadcastSync('admin-booking-updated');
    res.json({booking});
  });

  app.put('/api/admin/bookings/:id/report', requireAdminReady, (req, res) => {
    const booking = db.bookings.find((b) => b.id === req.params.id);
    if (!booking) {
      res.status(404).json({error: 'NOT_FOUND', message: 'Booking not found.'});
      return;
    }

    const {reportResults, reportRemarks, verifiedBy, reportPublished} = req.body as {
      reportResults?: ReportParameter[];
      reportRemarks?: string;
      verifiedBy?: string;
      reportPublished?: boolean;
    };

    if (Array.isArray(reportResults)) {
      booking.reportResults = reportResults;
    }
    if (reportRemarks !== undefined) booking.reportRemarks = reportRemarks;
    booking.verifiedBy = verifiedBy || 'Toseef Gulistan (M.D — Al-Hayat Lab Mirpur)';

    if (reportPublished !== undefined) {
      booking.reportPublished = Boolean(reportPublished);
      if (booking.reportPublished) {
        booking.reportPublishedAt = new Date().toISOString();
        booking.status = 'Report Ready';
      }
    }

    booking.updatedAt = new Date().toISOString();
    saveDatabase(db);
    broadcastSync('admin-report-updated');
    res.json({booking});
  });

  app.delete('/api/admin/bookings/:id', requireAdminReady, (req, res) => {
    const idx = db.bookings.findIndex((b) => b.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({error: 'NOT_FOUND', message: 'Booking not found.'});
      return;
    }
    db.bookings.splice(idx, 1);
    saveDatabase(db);
    broadcastSync('admin-booking-deleted');
    res.json({ok: true});
  });

  // Test & Pricing Management
  app.post('/api/admin/tests', requireAdminReady, (req, res) => {
    const {name, nameUr, department, price, sampleType, turnaround, fastingRequired, popular} =
      req.body as Partial<LabTest>;

    if (!name?.trim()) {
      res.status(400).json({error: 'VALIDATION_ERROR', message: 'Test name is required.'});
      return;
    }

    const nextNum = db.tests.length + 1;
    const newTest: LabTest = {
      id: `test-${Date.now()}`,
      code: `AHL-${String(nextNum).padStart(3, '0')}`,
      name: name.trim(),
      nameUr: nameUr?.trim() || undefined,
      department: (department as DepartmentType) || 'Biochemistry',
      price: Math.max(0, Number(price) || 500),
      sampleType: sampleType?.trim() || 'Blood (Serum)',
      turnaround: turnaround?.trim() || 'Same Day (4–6 Hrs)',
      fastingRequired: Boolean(fastingRequired),
      popular: Boolean(popular),
      active: true,
    };

    db.tests.unshift(newTest);
    saveDatabase(db);
    broadcastSync('admin-test-created');
    res.status(201).json({test: newTest});
  });

  app.patch('/api/admin/tests/:id', requireAdminReady, (req, res) => {
    const test = db.tests.find((t) => t.id === req.params.id);
    if (!test) {
      res.status(404).json({error: 'NOT_FOUND', message: 'Test not found.'});
      return;
    }

    const patch = req.body as Partial<LabTest>;
    if (patch.name !== undefined && patch.name.trim()) test.name = patch.name.trim();
    if (patch.nameUr !== undefined) test.nameUr = patch.nameUr.trim() || undefined;
    if (patch.department !== undefined) test.department = patch.department;
    if (patch.price !== undefined) test.price = Math.max(0, Math.round(Number(patch.price) || 0));
    if (patch.sampleType !== undefined) test.sampleType = patch.sampleType;
    if (patch.turnaround !== undefined) test.turnaround = patch.turnaround;
    if (patch.fastingRequired !== undefined) test.fastingRequired = Boolean(patch.fastingRequired);
    if (patch.popular !== undefined) test.popular = Boolean(patch.popular);
    if (patch.active !== undefined) test.active = Boolean(patch.active);

    saveDatabase(db);
    broadcastSync('admin-test-updated');
    res.json({test});
  });

  app.post('/api/admin/tests/bulk-price', requireAdminReady, (req, res) => {
    const {department, percentChange, flatChange} = req.body as {
      department?: string;
      percentChange?: number;
      flatChange?: number;
    };

    let updatedCount = 0;
    for (const test of db.tests) {
      if (department && department !== 'ALL' && test.department !== department) continue;
      let nextPrice = test.price;
      if (percentChange !== undefined && Number(percentChange) !== 0) {
        nextPrice = nextPrice * (1 + Number(percentChange) / 100);
      }
      if (flatChange !== undefined && Number(flatChange) !== 0) {
        nextPrice = nextPrice + Number(flatChange);
      }
      // Round cleanly to nearest 10 PKR
      test.price = Math.max(50, Math.round(nextPrice / 10) * 10);
      updatedCount++;
    }

    saveDatabase(db);
    broadcastSync('admin-bulk-price');
    res.json({updatedCount, tests: db.tests});
  });

  app.delete('/api/admin/tests/:id', requireAdminReady, (req, res) => {
    const idx = db.tests.findIndex((t) => t.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({error: 'NOT_FOUND', message: 'Test not found.'});
      return;
    }
    db.tests.splice(idx, 1);
    saveDatabase(db);
    broadcastSync('admin-test-deleted');
    res.json({ok: true});
  });

  // Packages Management
  app.post('/api/admin/packages', requireAdminReady, (req, res) => {
    const body = req.body as Partial<HealthPackage>;
    if (!body.name?.trim()) {
      res.status(400).json({error: 'VALIDATION_ERROR', message: 'Package name is required.'});
      return;
    }

    const pkg: HealthPackage = {
      id: `pkg-${Date.now()}`,
      code: `PKG-0${db.packages.length + 1}`,
      name: body.name.trim(),
      nameUr: body.nameUr?.trim() || body.name.trim(),
      targetAudience: body.targetAudience?.trim() || 'Comprehensive health checkup',
      targetAudienceUr: body.targetAudienceUr?.trim() || 'مکمل طبی چیک اپ',
      description: body.description?.trim() || '',
      descriptionUr: body.descriptionUr?.trim() || '',
      includedTests: Array.isArray(body.includedTests) ? body.includedTests : [],
      originalPrice: Math.max(0, Number(body.originalPrice) || 0),
      packagePrice: Math.max(0, Number(body.packagePrice) || 0),
      turnaround: body.turnaround || 'Same Day (4–6 Hrs)',
      homeCollectionFree: Boolean(body.homeCollectionFree),
      active: body.active !== undefined ? Boolean(body.active) : true,
    };

    db.packages.push(pkg);
    saveDatabase(db);
    broadcastSync('admin-package-created');
    res.status(201).json({package: pkg});
  });

  app.patch('/api/admin/packages/:id', requireAdminReady, (req, res) => {
    const pkg = db.packages.find((p) => p.id === req.params.id);
    if (!pkg) {
      res.status(404).json({error: 'NOT_FOUND', message: 'Package not found.'});
      return;
    }
    const patch = req.body as Partial<HealthPackage>;
    if (patch.name !== undefined) pkg.name = patch.name;
    if (patch.nameUr !== undefined) pkg.nameUr = patch.nameUr;
    if (patch.targetAudience !== undefined) pkg.targetAudience = patch.targetAudience;
    if (patch.description !== undefined) pkg.description = patch.description;
    if (patch.includedTests !== undefined) pkg.includedTests = patch.includedTests;
    if (patch.originalPrice !== undefined) pkg.originalPrice = Math.max(0, Number(patch.originalPrice) || 0);
    if (patch.packagePrice !== undefined) pkg.packagePrice = Math.max(0, Number(patch.packagePrice) || 0);
    if (patch.turnaround !== undefined) pkg.turnaround = patch.turnaround;
    if (patch.homeCollectionFree !== undefined) pkg.homeCollectionFree = Boolean(patch.homeCollectionFree);
    if (patch.active !== undefined) pkg.active = Boolean(patch.active);

    saveDatabase(db);
    broadcastSync('admin-package-updated');
    res.json({package: pkg});
  });

  app.delete('/api/admin/packages/:id', requireAdminReady, (req, res) => {
    const idx = db.packages.findIndex((p) => p.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({error: 'NOT_FOUND', message: 'Package not found.'});
      return;
    }
    db.packages.splice(idx, 1);
    saveDatabase(db);
    broadcastSync('admin-package-deleted');
    res.json({ok: true});
  });

  // Reviews Moderation
  app.patch('/api/admin/reviews/:id', requireAdminReady, (req, res) => {
    const rev = db.reviews.find((r) => r.id === req.params.id);
    if (!rev) {
      res.status(404).json({error: 'NOT_FOUND', message: 'Review not found.'});
      return;
    }
    if (req.body.approved !== undefined) rev.approved = Boolean(req.body.approved);
    saveDatabase(db);
    broadcastSync('admin-review-updated');
    res.json({review: rev});
  });

  app.delete('/api/admin/reviews/:id', requireAdminReady, (req, res) => {
    const idx = db.reviews.findIndex((r) => r.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({error: 'NOT_FOUND', message: 'Review not found.'});
      return;
    }
    db.reviews.splice(idx, 1);
    saveDatabase(db);
    broadcastSync('admin-review-deleted');
    res.json({ok: true});
  });

  // Lab Settings Update
  app.put('/api/admin/settings', requireAdminReady, (req, res) => {
    const nextSettings = req.body as Partial<LabSettings>;
    db.settings = {
      ...db.settings,
      ...nextSettings,
      homeCollectionFee: Math.max(0, Number(nextSettings.homeCollectionFee ?? db.settings.homeCollectionFee)),
      freeHomeCollectionThreshold: Math.max(
        0,
        Number(nextSettings.freeHomeCollectionThreshold ?? db.settings.freeHomeCollectionThreshold)
      ),
    };
    saveDatabase(db);
    broadcastSync('admin-settings-updated');
    res.json({settings: db.settings});
  });

  // ============================================================================
  // VITE DEV MIDDLEWARE OR PRODUCTION STATIC ASSETS
  // ============================================================================
  const httpServer = http.createServer(app);

  if (process.env.NODE_ENV !== 'production') {
    const disableHmr = process.env.DISABLE_HMR === 'true';
    const {createServer: createViteServer} = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: disableHmr ? false : {server: httpServer},
        watch: disableHmr ? null : {},
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Al-Hayat Lab Mirpur server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
