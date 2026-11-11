# Skylight private API: working notes

Sources read (cloned, not modified):

| Ref | Repo | Last commit | Role |
|---|---|---|---|
| **HA** | `logich/skylight_calendar` (`custom_components/skylight/`: `api.py`, `config_flow.py`, `const.py`, `people.py`, `calendar.py`) | 2026-10-26 | **Primary** for auth and event/tag shape. Written against the live API with `Skylight-Api-Version: 2026-05-01`. |
| **iOS** | `logich/Skylight-swift` (`SkylightEndpoint.swift`, `CalendarEvent.swift`, `AuthenticationManager.swift`, docs) | 2026-02-03 | Secondary. Predates Skylight's OAuth move. Endpoint paths and event models are still useful. Its auth is out of date. |

Skylight has no public API; §1–§5 started as notes from those two reverse-engineered repos. **Since 2026-11-11 the parts this server uses are verified against the live API** (laptop probes and calls from Lambda; results in §6, code in `internal/skylight`, `internal/calendar`, `internal/grant`). Where a statement below was corrected by a live call, it says so. Still unverified: anything about writes (§4.3, v2), refresh-token idle expiry, and 429 behaviour.

Decision: follow HA for auth (OAuth authorization code + PKCE, refresh token). Do not use the iOS `/api/sessions` password flow.

---

## 1. Base

- Base URL: `https://app.ourskylight.com`
- Request headers: `Authorization: Bearer <access_token>`, `Accept: application/json`, `Skylight-Api-Version: 2026-05-01`. HA also sends a browser `User-Agent`; **verified not required** (the server sends `skylight-mcp`). The version header **is** required: without it the server answers as `2026-01-01`.
- Format: JSON:API-flavoured responses (`data[]`, `included[]`, `relationships`). **Request bodies for calendar events are plain JSON, not JSON:API envelopes** (HA, "confirmed flat"). Other resources (lists, task box) are unverified.
- Timeouts: 20 s for API calls and 15 s for token calls (as HA); the server's token refresh is further capped at 4 s inside the lease.
- Rate limits: undocumented, and none seen live (no 429, no `Retry-After`). The client honours `Retry-After` (capped at 10 s) or uses jittered exponential backoff, at most 3 attempts within the request deadline.

## 2. Authentication

### 2.1 HA flow (use this)

OAuth 2.0 authorization code with PKCE (S256), public client:

| Item | Value |
|---|---|
| Authorize URL | `https://app.ourskylight.com/oauth/authorize` |
| Token URL | `https://app.ourskylight.com/oauth/token` |
| `client_id` | `skylight-mobile` |
| `scope` | `everything` |
| `redirect_uri` | `https://ourskylight.com/welcome`, the **only** registered URI. Nothing listens there; the user copies the `?code=` value out of the browser address bar. |

Authorize request query: `client_id`, `response_type=code`, `scope`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `prompt=login`.

Code exchange (`POST` token URL, form-encoded):
`grant_type=authorization_code`, `code`, `client_id`, `redirect_uri`, `code_verifier`, `scope`, `source=js-mobile`, plus device fields below.

Refresh (`POST` token URL, form-encoded):
`grant_type=refresh_token`, `refresh_token`, `client_id`, `scope=everything`, `source=web`, plus device fields.

Device fields (sent on both, full names): `skylight_api_client_device_fingerprint` (32 hex characters, generated once per grant), `skylight_api_client_device_platform=web`, `skylight_api_client_device_name` (HA: `home-assistant`; this server: `skylight-mcp`), `skylight_api_client_device_os_version` (this server: `unknown`), `skylight_api_client_device_app_version=unknown`, `skylight_api_client_device_hardware=3`.

Response (verified): `access_token`, `refresh_token`, `expires_in` (24 h), `created_at`, `scope`, `token_type`. HA ignores `expires_in` and refreshes reactively on 401. This server does both: it refreshes 5 minutes before the stored expiry, and once on a 401.

Key properties:

- **Refresh tokens rotate on every use** (verified). HA serialises refreshes with a lock, assuming a second concurrent refresh with the old token fails. **Live probes say otherwise:** simultaneous refreshes both succeed, and a spent token stays valid until its successor's access token is used (Doorkeeper semantics; see §6, rotation hazards). The lease still matters (§7).
- A refresh token may be bound to the `device_fingerprint` it was issued with, so the fingerprint must be stored with it and sent back unchanged.
- Token-endpoint failures: HTTP 400/401/403 means the credential is bad (treat as "re-authorise needed"). Anything else (5xx, 429) is the service being unavailable and must **not** be treated as signed-out.
- Sign-out everywhere, password change or server-side revoke invalidates the grant, and then a human must redo the browser step.
- Bootstrap (as built): `cmd/skylight-login` does the browser step and saves the grant locally (mode 0600); `cmd/skylight-store-import` moves it, with the frame id, into the DynamoDB table `SkylightMcpGrant` and deletes the local copy. The server never sees the password. The `/welcome` page rewrites the address bar at once, so the code is caught in the browser's Network tab.

### 2.2 iOS flow (do not use) — disagreement #1

- `POST /api/sessions` with `{email, password}` returns `{token, user_id}`.
- Subsequent requests use **`Authorization: Basic base64(userId:token)`**, not Bearer.
- No refresh at all ("if the token expires, the user needs to log in again").
- HA's history shows a password login existed (2025-12-04, "Log in with username and password") and was replaced by OAuth in July 2026. ⚠ Whether `/api/sessions` still works is unknown. I will not rely on it.

## 3. Endpoints we need

`{fid}` = frame id (household). Paths are the same in both repos unless noted.

| Purpose | Request | Notes |
|---|---|---|
| List frames | `GET /api/frames` | Verified. `data[].id`, `attributes.household_name`, `attributes.name` (slug) and `attributes.timezone`. The frame id is stored in the grant item at import; the client reads the frame's timezone from this list (a single-frame `GET /api/frames/{fid}` is not used, as it is unverified). |
| Family members / categories | `GET /api/frames/{fid}/categories?include_profiles=true` | Verified; shape in §6 (#1). **Family members are categories with `linked_to_profile: true`.** |
| Events | `GET /api/frames/{fid}/calendar_events?date_min=YYYY-MM-DD&date_max=YYYY-MM-DD&timezone=<IANA>&include=categories` | Verified. **`include=categories` is mandatory** (without it the relationship key is `category` and the parser rejects the document). Window is date-granular and **`date_max` is exclusive**. Recurring events come back one row per occurrence. No pagination seen. |
| Create event (v2) | `POST /api/frames/{fid}/calendar_events` | Flat JSON, see §4. |
| Update event (v2) | `PUT /api/frames/{fid}/calendar_events/{id}` | Flat, partial: only keys present change. |
| Delete event (v2) | `DELETE /api/frames/{fid}/calendar_events/{id}` | Empty body. |
| Source calendars | `GET /api/frames/{fid}/source_calendars` | Not needed for v1. |

There is **no single-event GET** (verified: 404 for every id form). `get_event` lists a window and filters by id. Occurrence ids (`<event>-<unix start>`) give the window. Other ids use the optional `around` hint, else -30/+180 days.

## 4. Data models

### 4.1 Event (JSON:API resource)

As first noted from the repos; the live shape is below this block.

```
data[]: {
  id: string,
  type: "calendar_event",              // iOS decodes `type`; HA ignores it
  attributes: {
    summary: string,                   // title
    description: string|null,
    location: string|null,
    all_day: bool,
    timezone: string|null,
    starts_at: string,                 // ISO 8601; HA uses dateutil parse
    ends_at: string,
    recurring: bool|null,              // iOS only
    rrule: [string]|null,              // iOS only
    calendar_id: string|null           // links to source calendar
  },
  relationships: {
    categories: { data: [ {id, type:"category"} ] }   // present only with include=categories
  }
}
included[]: {
  id, type: "category",
  attributes: { label: string, color: string|null,
                profile_pic_url: string|null, linked_to_profile: bool }
}
```

(Wire keys are snake_case; iOS decodes with a camelCase strategy.)

**Live shape (verified, what the parser relies on):** `type` is always `calendar_event` and the parser asserts it. `starts_at`/`ends_at` are RFC 3339 with milliseconds and an offset (all-day: local midnight to midnight, end exclusive). `all_day` is a required boolean. `summary`, `description`, `location` and `timezone` are optional strings. `recurring` is a boolean. `rrule` is null or a list of `RRULE:` strings. Further attributes exist and are ignored: `calendar_id`, `master_event_id`, `uid`, `source`, `editable`, `status`, `kind`, `lat`/`lng`, `owner_email`, `invited_emails` (personal data: never logged). Included categories carry `label`, `color`, `linked_to_profile` and `selected_for_chore_chart`; there is no `profile_pic_url`.

### 4.2 The event → family-member tag

1. Event `relationships.categories.data[]` lists category ids.
2. Resolve each id against `included[]` entries of `type == "category"`.
3. **Family member = category with `attributes.linked_to_profile == true` and a non-empty `label`.** Other categories are calendar buckets (e.g. "US Holidays") and must be dropped.
4. Name = `attributes.label` (trimmed). Order = Skylight's order. De-duplicate by name.

Disagreement #2: **iOS treats every category as an attendee** (comment: "include all categories as attendees") and never checks `linked_to_profile`. HA filters on it. Followed HA: the server **drops** non-member categories (for example holiday calendars). Observed live: Skylight also marks some non-person categories as linked to a profile (for example "Family" and a shared building calendar), so they appear as members. That is the household's own setup, not a parsing error.

### 4.3 Create / update body (HA, flat JSON)

`summary`, `starts_at`, `ends_at`, `all_day`, `timezone`, `kind="standard"`, optionally `description`, `location`, `category_ids` (family members assigned by category id), `calendar_account_id`/`calendar_id` (omit to land on the frame's own calendar), `rrule`. Null fields are omitted (the API rejects explicit nulls). Assigning by member **name** therefore needs a name→category id lookup via `/categories`.

Disagreement #3: iOS names the same fields `categoryIds`, `startsAt`, etc. under a camelCase encoder and omits `kind`; same intent, different casing assumptions. ⚠ Needs one live write to confirm required fields.

## 5. Where the two implementations disagree (summary)

| # | Topic | iOS | HA | Decision |
|---|---|---|---|---|
| 1 | Auth | `POST /api/sessions`, Basic `userId:token`, no refresh | OAuth code + PKCE, Bearer, rotating refresh token | HA |
| 2 | What counts as a family member | every category | `linked_to_profile == true` only | HA |
| 3 | Write field naming / `kind` | camelCase, no `kind` | snake_case, `kind: "standard"` | HA, verify live |
| 4 | Docs vs code in iOS repo | `api_integration_guide.md` describes `/api/v1/frames/{id}/calendar/events?startDate=`, `{"events":[...]}` | the iOS *code* actually calls `/api/frames/{fid}/calendar_events?date_min=` with JSON:API | **Ignore the iOS guide's paths and shapes**; they do not match any code. Likely speculative. |
| 5 | API version header | none | `Skylight-Api-Version: 2026-05-01` | HA. Pin it, so a server-side change is detectable. |
| 6 | Frame fields | doc: `timezone`, `memberCount` | `household_name` / slug `name` | HA |

Other notes from the iOS repo: `skylight_api_resources.md` calls the API "GraphQL" in one place and lists paths like `/calendar` and `/family`. Both are wrong against the actual code. Disregard.

## 6. Live verification (2026-11-11; outside CI)

Confirmed live on 2026-11-11 (first sign-in via `skylight-login`, one `GET /api/frames`):
- The code flow works with HA's fields, but `/welcome` rewrites the address bar immediately; the code must be caught in the browser's Network tab ("Preserve log").
- Code exchange returns `access_token` and `refresh_token` (43 characters each) and an `expires_in` of 24 hours.
- `GET /api/frames` with Bearer + `Skylight-Api-Version: 2026-05-01` → 200, JSON:API (`data`, `included`, `meta`), one frame. The response echoes `Skylight-Api-Version: 2026-05-01`, so a version change is detectable. Frame attributes include `household_name`, `name` **and `timezone`**, so the frame's own timezone is available for event windows.

Probe results, 2026-11-11 (`cmd/skylight-probe`, laptop, read-only; raw responses in git-ignored `captures/`). Answers to the numbered unknowns below:

| # | Answer |
|---|---|
| 1 | `GET /categories?include_profiles=true` → `data[]` of **type `category_detail`** (not `category`) with `label`, `color` (`#rrggbb`), `linked_to_profile`, `profile_picture_urls`, `selected_for_chore_chart`; relationships `family_member`, `avatar`, `hat`, `source_calendars`, `source_calendar_categorizations`; `included` holds `avatar`s. 17 categories, 11 with `linked_to_profile=true`, member labels non-empty and unique. Every category id referenced by an event exists here. |
| 2 | **No single-event GET**: `GET .../calendar_events/{id}` → 404 for plain ids, composite ids and a recurring event's base id. |
| 3 | Refresh **rotates every time** (new, different `refresh_token`); response fields `access_token, created_at, expires_in, refresh_token, scope, token_type`; `expires_in` 24 h for both code exchange and refresh. |
| 4 | Browser `User-Agent` **not required** (a plain UA gets 200). **`Skylight-Api-Version` matters**: without it the server answers as `2026-01-01`. Always send it, and treat a different echo as "upstream API changed". |
| 5 | Not provoked (no 429 seen; no `Retry-After` on any response). Still open. |
| 6 | Recurring events are **expanded per occurrence** within the window: each row has a distinct id, composite **`<event id>-<unix start time>`** for occurrences, plain digits otherwise; `recurring=true` rows carry `rrule` as a list of `RRULE:…` strings; `master_event_id` is mostly null; `uid` is shared across occurrences. No duplicate ids. |
| 7 | All-day events: `starts_at`/`ends_at` are full timestamps at **local midnight** with offset (`YYYY-MM-DDT00:00:00.000±hh:mm`), end = start + N days (exclusive end). Timed events use the same format with milliseconds. **`date_max` is exclusive**: the window is `[date_min, date_max)`; `date_min == date_max` returns nothing. |
| 8 | Write behaviour not probed (v2). |

Also observed: no pagination (`meta`/`links` absent) for 106 events over 37 days. With `include=categories`, events' relationship key is **`categories`** and `included` holds only `category` resources (attributes `label`, `color`, `linked_to_profile`, `selected_for_chore_chart`). **Without** it, the key is **`category`** (singular) and `included` still carries categories plus `event_notification_setting` and `calendar_account`: always send `include=categories` and parse only `categories`. Event attributes include `source` (`caldav`, `skylight`, `magic_import`, `ics_link`), `editable`, `status`, `kind="standard"`, `timezone`, `location`, `lat`/`lng`, `owner_email`, `invited_emails` (personal data: never log). 101 of 106 events carry a family member; 5 carry only non-member categories.

**Design consequence for `get_event`:** an occurrence id encodes its start time (`<id>-<unix seconds>`), so the tool can derive a narrow window from the id itself; plain ids need the caller's `start`/`end` hint (or a default window).

**Rotation hazards** (`skylight-probe -hazards`, owner-approved, 2026-11-11). The server behaves like Rails Doorkeeper with `revoke_previous_refresh_token_on_use`:
- A spent refresh token T1 **stays valid until the new access token (from T2's response) is first used**. Reusing T1 2 s and 90 s after rotation, without touching the new access token, was accepted and issued yet another new pair.
- Once the new access token has been used, reusing T1 → **HTTP 400 `invalid_grant`**.
- A rejected reuse **does not revoke the chain**: T2 and its access token kept working.
- Two simultaneous refreshes of one token **both succeed** with different new refresh tokens; the first winner's token refreshes fine afterwards.

Design consequences (PLAN §4):
- **Order is commit, then use**: persist the new refresh token before the new access token is used. A crash after refresh but before commit loses nothing: the old token still works because the new access token was never used. Using the new access token before committing is the one way to lose the grant.
- A refresh that gets `invalid_grant` most likely lost a race to another invocation that has since used its new token: re-read the store and retry with the stored token before declaring "re-authorise". The lease still matters, because without it two invocations can commit divergent tokens, and the one whose access token is used first revokes the other's parent.

**From AWS Lambda** (us-east-2, canary invoke, 2026-11-11): no datacenter-IP blocking. API reads (frames list, categories, 7-day events) and a token refresh both succeed from Lambda with a plain `User-Agent`; the lease/commit cycle ran as designed (generation 0 → 1, lease released, new 24 h token used only after the commit).

Still open (need time): refresh-token idle expiry, 429 behaviour, and everything about writes (#8).

The original questions, answered by the table above in the same order: (1) categories shape, (2) single-event GET, (3) token lifetime and rotation, (4) required headers, (5) 429 and `Retry-After`, (6) recurring events, (7) all-day format and `date_max`, (8) create fields and `category_ids`.

## 7. Implications for the server design

As built (`internal/grant`, `internal/calendar`):

- **Refresh-token rotation + Lambda concurrency.** The grant is one DynamoDB item (KMS-encrypted, strongly consistent reads, conditional writes). A refresher takes a 10-second lease, re-reads, refreshes with a 4-second deadline, and **commits the new tokens before the new access token is used**. On `invalid_grant` it re-reads before giving up. No reserved concurrency (the account limit is 10) and no Secrets Manager.
- **A failed refresh is not recoverable by the server**; it needs a human re-authorisation (`skylight-login`, then `skylight-store-import -overwrite`). Tools say so plainly, and the canary reports `error_class: reauthorize`.
- Rate limiting: `Retry-After` honoured (capped at 10 s), else capped exponential backoff with jitter, at most 3 attempts and never past the request deadline.
- Shape-change detection: missing `data`, wrong types, wrong resource types, events without `relationships.categories`, categories missing from `included`, missing `starts_at`/`ends_at`, an end before the start, or a different `Skylight-Api-Version` echo all return "upstream API changed". No event is silently skipped.
