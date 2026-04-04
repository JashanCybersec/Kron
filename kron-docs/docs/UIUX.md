# KRON — UI/UX Design Specification

**Version:** 1.0  
**Stack:** SolidJS (web) + Flutter (mobile)  
**Design philosophy:** Information-dense, action-oriented, zero learning curve for non-security users

---

## Design Principles

1. **Triage first.** The most critical information is visible without scrolling. P1 alerts demand attention before anything else.
2. **Action in 3 taps.** Any response action — block IP, isolate machine, create ticket — takes at most 3 clicks from landing on the alert.
3. **Plain language always.** No raw log data shown to non-expert users. Every screen has a plain-English summary above the technical detail.
4. **India-first defaults.** Default timezone: Asia/Kolkata. Default language: Hindi or English (user preference). Currency: ₹. Date format: DD/MM/YYYY.
5. **Works on a 1080p monitor.** No assumption of 4K displays. Target: 1920×1080 at 100% zoom.

---

## Colour System

### Severity Colours
| Level | Background | Text | Usage |
|---|---|---|---|
| P1 Critical | `#FEE2E2` | `#991B1B` | Immediate threat, active attack |
| P2 High | `#FEF3C7` | `#92400E` | High-risk, investigate today |
| P3 Medium | `#FEF9C3` | `#854D0E` | Review this week |
| P4 Low | `#DBEAFE` | `#1E40AF` | Informational, low urgency |
| P5 Info | `#F3F4F6` | `#374151` | Logged for compliance |

### Status Colours
| Status | Colour |
|---|---|
| Open | `#EF4444` |
| Acknowledged | `#F59E0B` |
| In progress | `#3B82F6` |
| Resolved | `#10B981` |
| False positive | `#6B7280` |

### System Colours
- Background primary: `#FFFFFF`
- Background secondary: `#F9FAFB`
- Background dark: `#111827`
- Text primary: `#111827`
- Text secondary: `#6B7280`
- Border: `#E5E7EB`
- Accent: `#4F46E5` (KRON brand purple)

### Dark Mode
Full dark mode support. All colours adapt. Dark background: `#0F172A`. Surface: `#1E293B`.

---

## Typography

| Use | Font | Weight | Size |
|---|---|---|---|
| Heading 1 | Inter | 600 | 24px |
| Heading 2 | Inter | 600 | 18px |
| Heading 3 | Inter | 500 | 16px |
| Body | Inter | 400 | 14px |
| Code / log | JetBrains Mono | 400 | 13px |
| Label | Inter | 500 | 12px |
| Caption | Inter | 400 | 11px |

---

## Web App — Screen Inventory

### 1. Login Screen

Clean minimal login. Logo top center. Two fields: email, password. TOTP field appears after valid credentials. "Forgot password" link. Language selector (EN/HI) top right.

No marketing, no onboarding prompts. Security tools should open fast.

---

### 2. Dashboard (Home)

**Layout:** Full-width, 12-column grid. Persistent left sidebar (240px) + top navbar (56px) + content area.

**Top ribbon (always visible):**
- KRON logo + org name
- Pipeline health indicator (green dot = healthy, yellow = degraded, red = down)
- Notification bell (unread P1/P2 count)
- User avatar + role badge
- Language toggle

**Left sidebar:**
```
KRON
─────────────────
⚡ Alert Queue    [P1: 2]
📊 Dashboard
🔍 Event Search
🎯 MITRE Map
📋 Cases
📏 Rules
🖥  Assets
👤 Users
📄 Compliance
⚙️  Settings
─────────────────
[Tenant selector] (MSSP only)
```

**Dashboard main content:**

Top row — 4 metric cards:
- Open P1/P2 alerts (red if >0)
- Events last 24h
- Agents online / total
- Compliance score (%)

Middle row — 2 panels:
- Alert trend (7-day bar chart by severity)
- Top 5 assets by risk score (ranked list with sparkline)

Bottom row — 2 panels:
- MITRE ATT&CK mini-heatmap (last 7 days, click to full view)
- Recent activity feed (last 10 alerts, most recent first)

---

### 3. Alert Queue

**The most used screen. Optimized for speed.**

**Header:** "Alert Queue" + filter bar + "Mark all read" + export button

**Filter bar (inline, no modal):**
- Severity: P1 / P2 / P3 / P4 / P5 (toggle buttons)
- Status: Open / Acknowledged / In Progress
- Date range: Today / 7d / 30d / Custom
- Asset: text search
- User: text search
- MITRE tactic: dropdown

**Alert list rows:**
```
[P1] [CRITICAL]  Suspicious login from Nigeria                    2 min ago
     accounts-server-01 · john.doe · T1078 · Risk: 92
     "User john.doe logged in from Nigeria at 2am — first time in 90 days"
     [Acknowledge] [Block IP] [Isolate] [View Details →]

[P2] [HIGH]     Beaconing detected to known C2                   14 min ago
     web-server-03 · system · T1071 · Risk: 78
     "Server making periodic connections every 30 seconds to flagged IP"
     [Acknowledge] [Block IP] [View Details →]
```

Clicking row expands inline detail panel (no page navigation).

**Inline detail panel:**
- Full narrative (EN + HI toggle)
- Evidence events (collapsible table of raw events)
- Root cause chain (visual timeline)
- Suggested playbook (one-click execute)
- MITRE ATT&CK mapping with description
- Asset info panel (criticality, owner, recent alerts)
- User info panel (role, baseline deviation, recent activity)
- Analyst notes (free text + @mention)
- Action log (all actions taken on this alert)

**Keyboard shortcuts:**
- `J/K` — navigate alerts
- `A` — acknowledge
- `Space` — expand/collapse detail
- `R` — mark resolved
- `F` — mark false positive

---

### 4. Event Search

**Purpose:** Investigative deep-dive into raw events.

**Layout:**
- Top: natural language query bar (prominent, center)
- Below: filter panel (collapsible, sidebar)
- Main: results table

**Query bar:**
```
┌─────────────────────────────────────────────────────────┐
│  🔍  Show all failed logins from 10.0.0.0/8 last 24h   │
│                                          [Search ↵]     │
└─────────────────────────────────────────────────────────┘
  Translated to SQL: SELECT * FROM events WHERE ...  [view]
```

Shows translated SQL (collapsible). Analyst can edit SQL directly if needed.

**Results table columns (configurable):**
Timestamp | Hostname | User | Source Type | Event Type | Src IP | Dst IP | Severity | Anomaly Score

Click any row → full event detail modal with all 60+ fields.

**Time range selector:** Compact calendar picker top-right. Presets: Last 1h / 6h / 24h / 7d / 30d / Custom.

---

### 5. MITRE ATT&CK Heatmap

**Full-screen MITRE matrix.** Each cell = one tactic/technique combination.

Cell colour intensity = number of alerts fired in selected time range.
- White: no detections
- Light amber: 1–5
- Medium amber: 6–20
- Dark amber: 21–100
- Red: 100+ (hot zone)

Hover: tooltip with technique name, count, last fired.
Click: filter alert queue to alerts with this technique.

Toggle buttons: 7d / 30d / 90d / All time.

"Coverage gaps" toggle: highlights techniques with no detection rules. Shows what KRON is NOT currently detecting.

---

### 6. Case Management

**Create cases from one or more alerts. Cases represent an investigation.**

**Case list:** Table with columns: Case ID, Name, Severity, Status, Assigned To, Created, Last Updated, Alert Count.

**Case detail:**

Timeline view (vertical, chronological):
```
09:15  ◉  Initial alert fired — Suspicious login
09:18  ○  Analyst acknowledged
09:22  ◉  Related alert — Lateral movement to FINANCE-SERVER
09:25  ◎  Analyst note: "Confirmed suspicious — investigating"
09:31  ◉  Related alert — Large data transfer detected
09:45  ◎  SOAR action: Host isolated
10:00  ◎  Analyst note: "Incident confirmed — notifying management"
11:30  ✓  Case resolved — credential compromise, user suspended
```

Right panel: asset map (which assets involved), user list, evidence attachments, compliance mapping (auto-populated).

---

### 7. No-Code Rule Builder

**Three modes (tab-based):**

**Mode 1: Visual Builder**
Drag-and-drop blocks:
- Event Filter (select source type, add field conditions)
- Threshold (count events, set rate limit)
- Sequence (event A then event B within time window)
- Aggregation (group by field, apply condition)
- Schedule (time-based conditions)
- Action (what to do when rule fires)

Real-time preview shows matched events from last 24h.
Estimated FP rate shown with colour coding (green <2%, yellow 2–10%, red >10%).

**Mode 2: SIGMA Import**
Paste SIGMA YAML → auto-parse → display as visual blocks → test → save.

**Mode 3: Advanced (SQL)**
Write raw ClickHouse SQL for power users. Test against historical data. Auto-generates SIGMA YAML for export.

---

### 8. Compliance Dashboard

**Per-framework tabs:** CERT-In / RBI / DPDP / SEBI

**Per-framework view:**
- Overall score (large number, colour-coded)
- Control list: each control with Pass ✓ / Fail ✗ / Warning ⚠
- Evidence count per control
- Days to next audit (countdown)
- "Generate Report" button (PDF + Excel)

**Report generation modal:**
- Date range selector
- Include/exclude specific controls
- Add auditor name (pre-populates report cover page)
- Download immediately or email to auditor

---

### 9. Settings

**Sections:**
- Organization — name, timezone, language, logo
- Notifications — WhatsApp number, email addresses, SMS fallback
- Integrations — Jira, PagerDuty, Slack, AD/LDAP
- Agents — fleet view, add agents, revoke agents
- Users & Roles — invite, set roles, deactivate
- Tenants (MSSP) — add/remove tenants, per-tenant config
- Backup — schedule, destination, last backup status
- AI Configuration — model mode (CPU/GPU), Mistral enable/disable
- System — version info, license, debug mode

---

## Mobile App (Flutter)

### Screen 1: Alert Feed

Full-screen vertical list of open P1/P2 alerts.

Each card:
- Severity badge (coloured)
- Alert title (large, readable at arm's length)
- Plain language summary (2 lines max)
- Asset + time
- Action buttons: Acknowledge / Block / Escalate / View

Pull-to-refresh. Push notifications on new P1 alerts even when app is in background.

### Screen 2: Approve SOAR Action

When a SOAR action requires approval, mobile user receives push notification:

```
KRON — Action Required

Isolate web-server-03?
This will disconnect the server from the network.

[Approve ✓]  [Reject ✗]  [View Details]
```

After tap → biometric auth required → action executes or rejects.

### Screen 3: Incident Summary

Simple text summary of open incidents. Suitable for reading in a meeting or while travelling.

### Screen 4: On-Call Schedule

Who is on-call now. Swap shifts. View shift history. Set phone as active/inactive for notifications.

---

## Accessibility

- All interactive elements have ARIA labels
- Keyboard navigable (no mouse required for core flows)
- Minimum contrast ratio: 4.5:1 (WCAG AA)
- Screen reader tested with NVDA (Windows) and VoiceOver (macOS)
- Font size respects browser/OS zoom settings
- No information conveyed by colour alone (always paired with text or icon)

---

## Responsive Behaviour

| Viewport | Layout |
|---|---|
| >1440px | Full layout, sidebar expanded |
| 1024–1440px | Sidebar collapsed to icons, content full width |
| 768–1024px | Sidebar hidden (hamburger), single column |
| <768px | Redirect to mobile app download (web app not optimized for mobile) |

---

## Loading States

- Page-level loading: skeleton screens (not spinners) matching layout shape
- Table loading: skeleton rows
- Chart loading: skeleton chart area
- Alert stream: existing alerts stay visible, new row fades in
- AI narrative: "Generating summary..." placeholder with subtle animation

---

## Error States

- Network error: "Unable to connect to KRON server" banner + retry button
- Query timeout: "Query took too long. Try a smaller time range." + suggested query
- No results: Contextual empty state with suggested next action (not just "No results")
- Permission denied: "Your role (Viewer) cannot perform this action. Contact your admin."

---

## Onboarding Flow (First Login)

5-step wizard (skippable after step 2):

1. **Welcome** — org name, admin name, timezone, language
2. **First agent** — copy/paste one-line install command for Linux or Windows
3. **Notifications** — enter WhatsApp number, send test message
4. **Compliance** — select applicable frameworks (CERT-In / RBI / DPDP / SEBI)
5. **Done** — show dashboard with "Waiting for first events..." state

Estimated completion: 8 minutes.
