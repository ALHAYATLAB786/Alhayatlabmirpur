# Al-Hayat Lab Mirpur — Firestore Zero-Trust Security Specification (Phase 0 TDD)

## 1. Data Invariants & Master Source of Truth

1. **Default-Deny Catch-All**: Every path not explicitly matched under `/databases/{database}/documents` is unconditionally denied (`allow read, write: if false;`).
2. **Verified Admin Gate (`isAdmin`)**:
   - Only authenticated Google accounts with `request.auth.token.email_verified == true` AND either:
     - `request.auth.token.email == 'toseefgulistan6@gmail.com'` (Bootstrapped Managing Director), OR
     - An existing role document at `/admins/$(request.auth.uid)`
   - Unverified email tokens (`email_verified == false`) are unconditionally rejected even if the email string matches `'toseefgulistan6@gmail.com'`.
3. **Public Catalog Singletons (`/settings/live`, `/catalog_state/live`)**:
   - Contain zero personal patient PII.
   - Readable via single-document `get` ONLY when the document ID equals `'live'` (`allow list` is denied).
   - Writable (`create`, `update`) strictly by `isAdmin()` with `updatedBy == request.auth.uid`, `createdAt == request.time` (immutable on update), `updatedAt == request.time`, and strict `hasAll`/`hasOnly` schema blueprints.
4. **Split-Collection PII Isolation (`/bookings_private/{bookingId}` vs `/booking_reports/{bookingId}`)**:
   - Patient phone numbers and residential addresses reside exclusively in `/bookings_private/{bookingId}`, readable and writable strictly by `isAdmin()`.
   - `allow list` on `/bookings_private` contains ZERO `get()`/`exists()` calls and enforces `isBootstrappedAdmin() && resource.data.adminEmail == 'toseefgulistan6@gmail.com'`.
   - `/booking_reports/{bookingId}` stores non-PII invoice/report verification status and clinical parameters, allowing single-document `get` by exact valid `bookingId` ONLY (`allow list: if false` prevents scraping).
5. **Atomicity Guarantee (`existsAfter`)**:
   - Creating or updating `/booking_reports/{bookingId}` requires `existsAfter(/databases/$(database)/documents/bookings_private/$(bookingId))` so an orphaned public report can never exist without its corresponding Admin private record.
6. **Terminal State Locking**:
   - Once a booking status reaches `'Completed'` or `'Cancelled'`, updates are blocked unless overridden by `isAdmin()`.

---

## 2. The "Dirty Dozen" Adversarial Payloads (Must All Return `PERMISSION_DENIED`)

1. **Payload 1 — Unverified Email Spoofing on `/settings/live`**:
   - Auth: `{ uid: "attacker1", token: { email: "toseefgulistan6@gmail.com", email_verified: false } }`
   - Target: `PUT /settings/live` -> Rejected by `request.auth.token.email_verified == true`.
2. **Payload 2 — Self-Assigned Admin Privilege Escalation on `/admins/attacker1`**:
   - Auth: `{ uid: "attacker1", token: { email: "attacker@gmail.com", email_verified: true } }`
   - Payload: `{ uid: "attacker1", email: "attacker@gmail.com", displayName: "Fake Admin", addedBy: "attacker1", createdAt: "<request.time>" }`
   - Target: `CREATE /admins/attacker1` -> Rejected because only `isBootstrappedAdmin()` may create `/admins/{adminUid}`.
3. **Payload 3 — Shadow / Ghost Field Injection on `/catalog_state/live`**:
   - Auth: Valid Bootstrapped Admin
   - Payload: Valid `CatalogStateDoc` + `{ "isSuperAdmin": true }`
   - Target: `UPDATE /catalog_state/live` -> Rejected by `data.keys().hasOnly(...)` and `affectedKeys().hasOnly(...)`.
4. **Payload 4 — PII Blanket Read on `/bookings_private/AHL-2026-1001`**:
   - Auth: `{ uid: "randomUser", token: { email: "patient@gmail.com", email_verified: true } }`
   - Target: `GET /bookings_private/AHL-2026-1001` -> Rejected (`isAdmin()` required).
5. **Payload 5 — Scraping Public Reports via `LIST /booking_reports`**:
   - Auth: Anonymous or Signed-in non-admin
   - Target: `LIST /booking_reports` -> Rejected (`allow list` is omitted/false; only `allow get` with valid `bookingId` is permitted).
6. **Payload 6 — ID Poisoning (2KB Junk Document ID) on `/booking_reports/{junkId}`**:
   - Auth: Valid Admin
   - Target: `CREATE /booking_reports/AAAA...[2000 chars]` -> Rejected by `isValidId(bookingId)` (`size() <= 128 && matches('^[a-zA-Z0-9_\\-]+$')`).
7. **Payload 7 — Identity Spoofing (`updatedBy` Mismatch)**:
   - Auth: Valid Admin (`uid: "admin_uid_1"`)
   - Payload: `LabSettingsDoc` with `updatedBy: "someone_else"`
   - Target: `UPDATE /settings/live` -> Rejected by `data.updatedBy == request.auth.uid`.
8. **Payload 8 — Forged Client Timestamp (`updatedAt != request.time`)**:
   - Auth: Valid Admin
   - Payload: `CatalogStateDoc` with `updatedAt: Timestamp(2020, 1, 1)`
   - Target: `UPDATE /catalog_state/live` -> Rejected by `incoming().updatedAt == request.time`.
9. **Payload 9 — Mutating Immutable `createdAt` Field**:
   - Auth: Valid Admin
   - Payload: `LabSettingsDoc` modifying `createdAt` during update
   - Target: `UPDATE /settings/live` -> Rejected by `incoming().createdAt == existing().createdAt` and `affectedKeys().hasOnly(...)` excluding `createdAt`.
10. **Payload 10 — Value Poisoning (1MB String on Allowed Key `labName`)**:
    - Auth: Valid Admin
    - Payload: `{ labName: "A".repeat(500000), ... }`
    - Target: `UPDATE /settings/live` -> Rejected by `isValidLabSettings(incoming())` (`data.labName.size() <= 120`).
11. **Payload 11 — Orphaned Public Report Write Without Private Booking (`existsAfter` Bypass)**:
    - Auth: Valid Admin
    - Target: `CREATE /booking_reports/AHL-2026-9999` without `/bookings_private/AHL-2026-9999` -> Rejected by `existsAfter(/databases/$(database)/documents/bookings_private/$(bookingId))`.
12. **Payload 12 — Unauthorized `LIST` on `/bookings_private` Without Relational Filter**:
    - Auth: Non-bootstrapped user or unfiltered query
    - Target: `LIST /bookings_private` -> Rejected unless `isBootstrappedAdmin() && resource.data.adminEmail == 'toseefgulistan6@gmail.com'`.

---

## 3. Red Team Audit Matrix (Phase 5 Verification)

| Collection | Shadow Update Test | Email Spoofing Test | PII Blanket Test | Query Trust Test | Value Poisoning Test |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/admins/{adminUid}` | PASS (`hasOnly` enforced) | PASS (`email_verified == true`) | PASS (Admin-only get) | PASS (`list` denied) | PASS (`isValidAdminRole` bounds all strings) |
| `/settings/{settingId}` | PASS (`hasOnly` + `affectedKeys`) | PASS (`email_verified == true`) | PASS (Zero PII stored) | PASS (`list` denied; `get` locked to `'live'`) | PASS (`isValidLabSettings` bounds all fields) |
| `/catalog_state/{stateId}` | PASS (`hasOnly` + `affectedKeys`) | PASS (`email_verified == true`) | PASS (Zero PII stored) | PASS (`list` denied; `get` locked to `'live'`) | PASS (`isValidCatalogState` bounds map sizes) |
| `/bookings_private/{bookingId}` | PASS (`hasOnly` + `affectedKeys`) | PASS (`email_verified == true`) | PASS (Admin-only get/write) | PASS (`resource.data.adminEmail` enforced, 0 `get()`) | PASS (`isValidBookingPrivate` wraps update) |
| `/booking_reports/{bookingId}` | PASS (`hasOnly` + `affectedKeys`) | PASS (`email_verified == true`) | PASS (No phone/address PII) | PASS (`list` denied; `get` requires `isValidId`) | PASS (`isValidBookingReport` wraps update + `existsAfter`) |
