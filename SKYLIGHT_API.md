# Skylight private API: working notes

Sources read (cloned, not modified):

| Ref | Repo | Last commit | Role |
|---|---|---|---|
| **HA** | `logich/skylight_calendar` (`custom_components/skylight/`: `api.py`, `config_flow.py`, `const.py`, `people.py`, `calendar.py`) | 2026-10-26 | **Primary** for auth and event/tag shape. Written against the live API with `Skylight-Api-Version: 2026-05-01`. |
| **iOS** | `logich/Skylight-swift` (`SkylightEndpoint.swift`, `CalendarEvent.swift`, `AuthenticationManager.swift`, docs) | 2026-02-03 | Secondary. Predates Skylight's OAuth move. Endpoint paths and event models are still useful. Its auth is out of date. |

**Nothing here has been verified against the live API by me.** Skylight has no public API. Everything below is reverse-engineered by those two repos. The first implementation task is to confirm each claim marked ⚠ with one real call (outside CI), then freeze scrubbed fixtures from the responses.

Decision: follow HA for auth (OAuth authorization code + PKCE, refresh token). Do not use the iOS `/api/sessions` password flow.

---

## 1. Base

- Base URL: `https://app.ourskylight.com`
- Request headers (HA): `Authorization: Bearer <access_token>`, `Accept: application/json`, `Skylight-Api-Version: 2026-05-01`, and a browser-style `User-Agent` (HA sends a Chrome UA, ⚠ unclear whether it is required).
- Format: JSON:API-flavoured responses (`data[]`, `included[]`, `relationships`). **Request bodies for calendar events are plain JSON, not JSON:API envelopes** (HA, "confirmed flat"). Other resources (lists, task box) are unverified.
- Timeouts HA uses: 20 s for API calls, 15 s for token calls.
- Rate limits: undocumented in both repos. Neither implements 429 handling beyond classification. We will implement backoff (see §7).

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

Device fields (sent on both): `skylight_api_client_device_fingerprint` (random hex, generated once per install), `_platform=web`, `_name`, `_os_version`, `_app_version=unknown`, `_hardware=3`.

Response: `access_token`, `refresh_token`. Expiry/`expires_in` is not read by HA; it refreshes **reactively on 401**, once, then retries the request.

Key properties:

- **Refresh tokens rotate on every use.** HA serialises refreshes with a lock because a second concurrent refresh with the old token fails. This is the main design hazard for a Lambda (see §7).
- A refresh token may be bound to the `device_fingerprint` it was issued with, so the fingerprint must be stored with it and sent back unchanged.
- Token-endpoint failures: HTTP 400/401/403 means the credential is bad (treat as "re-authorise needed"). Anything else (5xx, 429) is the service being unavailable and must **not** be treated as signed-out.
- Sign-out everywhere, password change or server-side revoke invalidates the grant, and then a human must redo the browser step.
- Bootstrap: a one-off local tool does the browser step and writes `{refresh_token, device_fingerprint}` to Secrets Manager. The server never sees the password.

### 2.2 iOS flow (do not use) — disagreement #1

- `POST /api/sessions` with `{email, password}` returns `{token, user_id}`.
- Subsequent requests use **`Authorization: Basic base64(userId:token)`**, not Bearer.
- No refresh at all ("if the token expires, the user needs to log in again").
- HA's history shows a password login existed (2025-12-04, "Log in with username and password") and was replaced by OAuth in July 2026. ⚠ Whether `/api/sessions` still works is unknown. I will not rely on it.

## 3. Endpoints we need

`{fid}` = frame id (household). Paths are the same in both repos unless noted.

| Purpose | Request | Notes |
|---|---|---|
| List frames | `GET /api/frames` | `data[].id`, `attributes.household_name` (display name) and `attributes.name` (generated slug, e.g. "byrd-malone-7772"). Single-frame accounts: auto-select. Plan: configure frame id once in the secret. |
| Family members / categories | `GET /api/frames/{fid}/categories?include_profiles=true` | **Family members are categories with `linked_to_profile: true`.** ⚠ Exact response shape: HA uses it only for sensors; confirm with a live call. |
| Events | `GET /api/frames/{fid}/calendar_events?date_min=YYYY-MM-DD&date_max=YYYY-MM-DD&timezone=<IANA>&include=categories` | **`include=categories` is mandatory**, otherwise tags are absent. Window is date-granular, not datetime. iOS also asks for `calendar_account,event_notification_setting`; not needed. |
| Create event (v2) | `POST /api/frames/{fid}/calendar_events` | Flat JSON, see §4. |
| Update event (v2) | `PUT /api/frames/{fid}/calendar_events/{id}` | Flat, partial: only keys present change. |
| Delete event (v2) | `DELETE /api/frames/{fid}/calendar_events/{id}` | Empty body. |
| Source calendars | `GET /api/frames/{fid}/source_calendars` | Not needed for v1. |

There is **no single-event GET** in either repo. `get_event` will be implemented as: list events and filter by id. ⚠ A narrow window around an unknown id is impossible, so either accept `start`/`end` hints, cache, or probe `GET .../calendar_events/{id}` live to see if it exists.

## 4. Data models

### 4.1 Event (JSON:API resource, `type` is not asserted by HA)

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

### 4.2 The event → family-member tag

1. Event `relationships.categories.data[]` lists category ids.
2. Resolve each id against `included[]` entries of `type == "category"`.
3. **Family member = category with `attributes.linked_to_profile == true` and a non-empty `label`.** Other categories are calendar buckets (e.g. "US Holidays") and must be dropped.
4. Name = `attributes.label` (trimmed). Order = Skylight's order. De-duplicate by name.

Disagreement #2: **iOS treats every category as an attendee** (comment: "include all categories as attendees") and never checks `linked_to_profile`. HA filters on it. Follow HA, otherwise holiday calendars appear as "people". The MCP will expose the non-member categories separately, or drop them.

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

## 6. Unknowns to resolve with live calls (outside CI, once)

1. `GET /categories?include_profiles=true` real shape (needed for `list_family_members`: id, name, colour).
2. Whether any `GET /calendar_events/{id}` exists.
3. Access-token lifetime, and whether refresh also returns a new `refresh_token` every time.
4. Whether the `User-Agent`/`Skylight-Api-Version` headers are required.
5. 429 behaviour and any `Retry-After`.
6. Recurring events: does one row come back per occurrence in the window or one master with `rrule`?
7. All-day event date format (bare date vs midnight timestamps) and the timezone semantics of `date_max` (inclusive?).
8. Required fields for create, and whether `category_ids` accepts only family-member categories.

## 7. Implications for the server design

- **Refresh-token rotation + Lambda concurrency.** Two concurrent invocations may both refresh with the same token; one fails and may invalidate the chain. Mitigation to decide in the plan: reserved concurrency of 1 plus read-modify-write of the secret (Secrets Manager `PutSecretValue`), and on a 400 from refresh re-read the secret once before failing.
- **A failed refresh is not recoverable by the server**; it needs a human re-authorisation. The error must say so plainly, and the daily canary should also catch it.
- Rate limiting: honour `Retry-After` if present, otherwise capped exponential backoff with jitter, a retry budget below the Lambda timeout.
- Shape-change detection: parsers must check the JSON:API structure and return "upstream API changed" on missing `data`, wrong types or an unexpected `Skylight-Api-Version` echo, rather than dropping events silently. Note HA currently *skips* events missing `starts_at`/`ends_at`; we must not.
