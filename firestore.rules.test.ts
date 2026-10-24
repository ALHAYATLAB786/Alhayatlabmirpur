/**
 * Firestore Security Rules Specification Test Suite ("Dirty Dozen" Payloads)
 * Verifies all 12 adversarial payloads against Al-Hayat Lab Mirpur Zero-Trust Rules.
 */

export interface DirtyDozenScenario {
  id: number;
  name: string;
  operation: 'get' | 'list' | 'create' | 'update' | 'delete';
  path: string;
  auth: {
    uid: string;
    email?: string;
    email_verified?: boolean;
  } | null;
  payload?: Record<string, unknown>;
  expectedOutcome: 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_SCENARIOS: DirtyDozenScenario[] = [
  {
    id: 1,
    name: 'Unverified Email Spoofing on /settings/live',
    operation: 'update',
    path: '/settings/live',
    auth: {uid: 'spoof-uid', email: 'toseefgulistan6@gmail.com', email_verified: false},
    payload: {labName: 'Spoofed Lab'},
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 2,
    name: 'Self-Assigned Admin Role Escalation on /admins/attacker1',
    operation: 'create',
    path: '/admins/attacker1',
    auth: {uid: 'attacker1', email: 'attacker@gmail.com', email_verified: true},
    payload: {
      uid: 'attacker1',
      email: 'attacker@gmail.com',
      displayName: 'Rogue User',
      addedBy: 'attacker1',
    },
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 3,
    name: 'Shadow Ghost Field Injection on /catalog_state/live',
    operation: 'update',
    path: '/catalog_state/live',
    auth: {uid: 'md-uid', email: 'toseefgulistan6@gmail.com', email_verified: true},
    payload: {isVerifiedShadow: true},
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 4,
    name: 'PII Blanket Read by Non-Admin Signed-In User on /bookings_private/AHL-2026-1001',
    operation: 'get',
    path: '/bookings_private/AHL-2026-1001',
    auth: {uid: 'patient-uid', email: 'patient@example.com', email_verified: true},
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 5,
    name: 'Collection Scraping via LIST on /booking_reports',
    operation: 'list',
    path: '/booking_reports',
    auth: null,
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 6,
    name: 'ID Poisoning with Illegal Characters on /booking_reports/bad$id!',
    operation: 'create',
    path: '/booking_reports/bad$id!',
    auth: {uid: 'md-uid', email: 'toseefgulistan6@gmail.com', email_verified: true},
    payload: {bookingId: 'bad$id!'},
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 7,
    name: 'Identity Spoofing with Mismatched updatedBy UID on /settings/live',
    operation: 'update',
    path: '/settings/live',
    auth: {uid: 'md-uid', email: 'toseefgulistan6@gmail.com', email_verified: true},
    payload: {updatedBy: 'forged-other-uid'},
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 8,
    name: 'Client-Forged Past Timestamp on /catalog_state/live',
    operation: 'update',
    path: '/catalog_state/live',
    auth: {uid: 'md-uid', email: 'toseefgulistan6@gmail.com', email_verified: true},
    payload: {updatedAt: '2020-01-01T00:00:00Z'},
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 9,
    name: 'Mutating Immutable createdAt on /settings/live',
    operation: 'update',
    path: '/settings/live',
    auth: {uid: 'md-uid', email: 'toseefgulistan6@gmail.com', email_verified: true},
    payload: {createdAt: '2026-10-24T00:00:00Z'},
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 10,
    name: 'Value Poisoning Oversized String on /settings/live',
    operation: 'update',
    path: '/settings/live',
    auth: {uid: 'md-uid', email: 'toseefgulistan6@gmail.com', email_verified: true},
    payload: {labName: 'X'.repeat(10000)},
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 11,
    name: 'Orphaned Report Write Without Matching /bookings_private Document',
    operation: 'create',
    path: '/booking_reports/AHL-2026-ORPHAN',
    auth: {uid: 'md-uid', email: 'toseefgulistan6@gmail.com', email_verified: true},
    payload: {bookingId: 'AHL-2026-ORPHAN'},
    expectedOutcome: 'PERMISSION_DENIED',
  },
  {
    id: 12,
    name: 'Unfiltered Non-Admin LIST on /bookings_private',
    operation: 'list',
    path: '/bookings_private',
    auth: {uid: 'other-uid', email: 'other@example.com', email_verified: true},
    expectedOutcome: 'PERMISSION_DENIED',
  },
];
