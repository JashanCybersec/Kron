# DesignPartnerPlaybook.md — KRON First Customer Strategy

**Why this file exists:** Technical milestones mean nothing if no real customer validates the product.
The 3 design partners are as important as any code milestone.
This file tells you how to find them, what to offer, and how to work with them.

---

## What a Design Partner Is

A design partner is NOT a regular customer.
A design partner is an organization that:
- Uses KRON Standard in production on their real infrastructure
- Gives weekly honest feedback (not just positive)
- Allows KRON to observe what's working and what's broken
- Is comfortable with occasional issues (paid nothing or very little)
- Gets KRON's complete attention when something breaks

In return, KRON gives them:
- Free or deeply discounted usage for 6–12 months
- Priority roadmap influence (their use cases get built first)
- Pricing locked for 3 years after they convert to paid
- Direct access to the founder for escalations

---

## Target Design Partner Profile

You need 3 design partners. Target these specific org types:

**Partner 1: Mid-size NBFC (100–500 employees)**
- Under RBI IT Framework and DPDP Act
- Has an IT manager but no dedicated security team
- Pain: getting fined for compliance gaps, worried about CERT-In
- Why they say yes: KRON makes their compliance problems go away
- Target: regional NBFCs, microfinance institutions, small cooperative banks

**Partner 2: Multi-location hospital or diagnostic chain**
- Under ABDM/NHA data guidelines and DPDP Act
- Patient data on local servers, no security monitoring
- Pain: DPDP liability, worried about patient data breach
- Why they say yes: KRON autopilot mode needs zero security staff
- Target: 50–200 bed hospitals, diagnostic chains like SRL/Metropolis franchisees

**Partner 3: Mid-size manufacturer or MSME**
- Under nothing specific but worried about ransomware
- Mix of Windows workstations, Linux servers, maybe OT
- Pain: one ransomware attack could shut them down for weeks
- Why they say yes: WhatsApp alerts + autopilot, no expertise needed
- Target: auto parts manufacturers, pharma, textile, food processing

---

## How to Find Them

**Warm outreach (most effective):**
- LinkedIn: search "IT Manager" + "NBFC" or "Chief Information Officer" + "hospital"
- DSCI (Data Security Council of India) member directory
- NASSCOM CTO forums
- Local CISO network groups (Bangalore, Mumbai, Delhi — active WhatsApp groups)
- CA/ICAI network — CAs advise NBFCs, will refer you

**Events (targeted):**
- DSCI Annual Information Security Summit
- BFSI Technology Conclave
- NASSCOM Product Conclave
- Regional events: PHD Chamber, FICCI tech events

**Cold outreach script (WhatsApp or email):**
```
Hi [Name],

I'm building KRON — a SIEM that runs completely on your own servers,
costs less than one employee's salary per year, and sends security
alerts to WhatsApp.

I'm looking for 3 organizations in India to try it free for 6 months
and help shape the product. In exchange, I need 30 minutes per week
of honest feedback.

Given your role at [org], you might be dealing with the kind of
compliance pressure (CERT-In/RBI/DPDP) that KRON is built to solve.

Worth a 20-minute call this week?

— Jashan
```

---

## What to Offer

**Terms for design partners:**
- KRON Standard: free for 6 months
- After 6 months: option to convert at 50% of standard pricing, locked for 3 years
- Requirement: 30-minute weekly feedback call
- Requirement: honest feedback — positive AND negative
- Requirement: allow KRON to reference them as a customer (optional if sensitive)

**What they get in writing:**
- No-cost agreement (simple 1-page MoU)
- Data stays on their servers (no data leaves their organization)
- KRON has no access to their data
- They can terminate and delete all data at any time
- Their feedback may influence the product but is not binding

---

## The First 30 Days With a Design Partner

**Day 1–3: Infrastructure**
- KRON installs on their server (you do this, remotely or on-site)
- Agents deployed on 5–10 critical servers (you do this via Ansible)
- Basic syslog sources connected (firewall, AD, key applications)
- First events in ClickHouse: verified together
- WhatsApp alert number configured: test alert sent to their phone

**Day 4–7: Calibration**
- Review first 100 alerts together: which are real, which are noise
- Tune false positive rules: suppress known-benign patterns
- Add custom rules for their environment (if obvious gaps)
- Verify CERT-In/compliance frameworks are mapping correctly

**Day 8–30: Monitoring**
- Weekly 30-minute call: what worked, what confused them, what's missing
- KRON founder on-call for any P1 incidents
- Track: are they actually using the product daily, weekly, never?
- Track: are they looking at alerts or ignoring them?

**What to learn from each call:**
- "What did you notice that surprised you this week?"
- "Was there anything confusing about an alert you received?"
- "Was there a security event you know happened that KRON didn't alert on?"
- "What's the one thing that would make you immediately recommend this to a peer?"
- "What's the one thing stopping you from recommending it right now?"

---

## Red Flags (Be Honest With Yourself)

If after 30 days:
- The design partner hasn't looked at the dashboard more than twice → the UX is wrong
- They're ignoring WhatsApp alerts → the alerts are too noisy or not actionable
- They asked you to just send them a weekly report → autopilot mode is the right feature, UI is not
- They keep asking "but where is my data going?" → the on-premise messaging isn't clear enough
- They say "this is great but too complex" → Nano is the right tier, not Standard

These are product signals. Not reasons to move on to the next customer.
Fix the problem first.

---

## Converting Design Partners to Paying Customers

At month 5 (one month before their free period ends), start the conversation:

**Conversation structure:**
1. "We're approaching the end of the free period. I want to understand what value you've gotten."
2. Get them to articulate the value in their own words (they sell themselves)
3. Present pricing: "Standard tier is [price]/month. Given that you said [their words], does that feel right?"
4. If they hesitate on price: "What price would feel right for the value you described?"
5. Do not discount more than 30% from standard pricing (destroys value perception)

**Target conversion price for first 3 customers:**
- NBFC: ₹8,000–15,000/month (much less than their compliance fine risk)
- Hospital: ₹5,000–10,000/month
- Manufacturer: ₹6,000–12,000/month

**If they won't convert:**
Ask directly: "What would need to be true for you to become a paying customer?"
Either build that thing (if it's reasonable) or accept they're not the right customer.
A non-paying design partner after 6 months is a signal, not a failure — move to the next one.
