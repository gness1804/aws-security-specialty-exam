# Phase 6 — Validation & exam mindset (Week 8)

**Domains trained:** all six — this phase is where you *integrate*. It leans hardest
on **Domain 4 (IAM, 16%)** because the single most valuable exam-day skill is reading
an authorization failure and naming the exact layer that caused it.

**The mindset shift:** Phases 1–5 built and broke real systems. Phase 6 builds the
*diagnostic reflex*: given a denial, an error string, or a missed practice question,
can you trace it to root cause **fast** — under exam time pressure — and say which of
SCP / identity policy / resource policy / permission boundary / session context
stopped the action? The deliverable of this phase isn't infrastructure. It's a
**repeatable RCA loop** and a **readiness gate** you don't cross until you're ready.

This is also the lightest phase to *deploy* and the heaviest to *think*. Two of the
three scenarios are protocol; the middle one is hands-on with read-only tools (the
IAM Policy Simulator and the STS authorization-message decoder) that never change a
thing — so you can drill them freely without cost or cleanup.

---

## How this lab works

Same active-recall format. Build/Break-Fix sections **pose the task and stop** —
sketch your answer, then check `answers/phase-6-answers.md` (keyed **B6.1**,
**D6.2**, …), the reference policies in `policies/phase-6/`, and the read-only
diagnostic tooling in `scripts/phase-6/`.

> **Cost note:** this phase is essentially free. The Policy Simulator and
> `decode-authorization-message` are read-only API calls. The only "cost" is the time
> for the timed exams. No teardown needed beyond not leaving prior phases running.

---

## Prerequisite

- Phases 1–5 complete, and your **practice exam #1 (Phase 5.3) scored and RCA'd** —
  Phase 6 turns that RCA table into drills.
- An IAM principal (user or role) you can run the simulator against in `scs-member`,
  plus the policies you wrote in earlier phases to test.
- A way to *trigger* a real `AccessDenied` (any earlier Break/Fix leaves you plenty).

> **Reading after the labs:** re-skim the **Exam Guide task statements** and your own
> Break/Fix notes (see `reading-list.md`, Phase 6).

---

## Scenario 6.1 — The RCA loop: turn every miss into a drill  ·  **Core**

### Goal
Take the RCA table from practice exam #1 and **recreate the underlying scenario in
the console/CLI** for every missed question — not re-read it, *rebuild* it — so the
miss converts into a muscle-memory drill. Then re-test the weak domain.

### Why the exam cares
The exam is scenario-based; you pass by **recognizing patterns you've handled**, not
by recalling trivia. A miss is a pattern you haven't internalized. Reading the
explanation patches the symptom; **rebuilding the scenario** patches the cause.

### The protocol · B6.1
1. For each "didn't know" row in your Phase 5.3 RCA table, **reproduce the scenario
   hands-on**: if you missed an SCP-vs-boundary question, build both and watch which
   wins (6.2 helps); if you missed a KMS grant question, redo Phase 1.2. Map each
   miss to its **owning phase/lab** and re-run that drill.
2. For each **"misread / time"** row, it's not a knowledge gap — log it as a
   **test-craft** item (see 6.3) and move on; don't waste a rebuild on it.
3. **Re-test the weakest domain** with a fresh question set. Did the rebuild move the
   number? If not, the rebuild was too shallow — go deeper (break it *harder*).

### Self-check · D6.1
- Can you state, for each rebuilt scenario, the **one sentence** the exam is testing?
  (e.g. "an explicit deny in an SCP beats an allow in an identity policy.")
- Which phase shows up most in your RCA table? That's your true weak spot regardless
  of overall score — weight Phase 6 effort there.

→ Reference: `answers/phase-6-answers.md` → **B6.1 / D6.1** (RCA-to-lab mapping table).

---

## Scenario 6.2 — IAM Policy Simulator + CloudTrail error-string drills  ·  **Core**

### Goal
Get fluent with the two tools that answer "**why** was this denied?": the **IAM
Policy Simulator** (predict allow/deny *before* running anything, including against a
permission boundary) and the **CloudTrail / STS error-string** workflow (read a real
denial and decode its **encoded authorization message** into the exact failing
statement).

### Why the exam cares
A large share of Domain 4 questions are a wall of policy JSON ending in "why does
principal X get AccessDenied on action Y?" The discriminator between the right and
wrong answer is almost always **which layer denied**: an **implicit deny** (no allow
anywhere), an **explicit deny** (in an identity policy, a resource policy, an SCP, or
exceeding a **permission boundary**), or a **missing condition/context value**. You
must know that the simulator returns an **`EvalDecision`** of
`allowed`/`explicitDeny`/`implicitDeny` plus **`MatchedStatements`** and
**`MissingContextValues`**; that it can simulate a **permissions boundary** and
**resource policy** but does **not** evaluate **SCPs** (org policies are separate);
and that a real denial's **encoded message** is decoded with
**`aws sts decode-authorization-message`**.

### Build challenge · B6.2
1. **Simulate before you run.** Using the simulator, test whether a principal can
   perform an action against a resource. What three fields tell you (a) the outcome,
   (b) *which* statement drove it, and (c) whether the deny is just a missing
   condition value? Which decision string means "nothing allowed it" vs "something
   explicitly forbade it"?
2. **Boundary drill.** Simulate an action that the identity policy **allows** but a
   **permission boundary** does not. What `EvalDecision` comes back, and why is the
   effective permission the **intersection** of policy and boundary?
3. **Decode a real denial.** Trigger an `AccessDenied` whose message includes an
   **encoded authorization message**, then decode it. What does the decoded JSON tell
   you that the raw error did not, and which CLI command does the decode?

> Hint: the simulator answers "*would* this be denied and by what." The decoded
> authorization message answers "this *was* denied and here's the exact context."
> Together they cover predict-vs-postmortem.

→ Reference: `answers/phase-6-answers.md` → **B6.2**. Test policies:
`policies/phase-6/6.2-simulator-test-policy.json`,
`policies/phase-6/6.2-permission-boundary.json`. Read-only tooling:
`scripts/phase-6/run_policy_simulator.py`,
`scripts/phase-6/decode_authorization_message.py`.

### Break it / Fix it · D6.2
1. **Read the message, name the layer.** For each real CloudTrail/CLI error phrasing
   below, say which layer denied and how you'd confirm it:
   (a) "...not authorized to perform... because no identity-based policy allows...";
   (b) "...with an explicit deny in a service control policy";
   (c) "...with an explicit deny in an identity-based policy";
   (d) "...because no resource-based policy allows...";
   (e) "...with an explicit deny in a permissions boundary".
2. The simulator says **`allowed`** but the real call gets **`AccessDenied`**. Name
   two reasons the simulator and reality can disagree (hint: one is a policy type the
   simulator doesn't evaluate; one is a runtime condition key).
3. A denial's error message has **no** encoded authorization message. What does that
   usually imply about *where* the deny happened, and what's your next diagnostic step?

→ `answers/phase-6-answers.md` → **D6.2**

---

## Scenario 6.3 — Timed exams #2 & #3 + the readiness gate  ·  **Core**

### Goal
Sit two more full-length, timed practice exams, drive your by-domain scores past the
gate, and decide — on evidence, not vibes — that you're ready to book the real thing.

### Why this matters
One good practice score can be luck or a friendly question set. **Two consecutive**
runs above the gate, *with no domain lagging*, is signal. The real exam's passing
scaled score is **750/1000**; you want practice margin above that because exam-day
conditions are harder than your desk.

### The protocol · B6.3
1. **Exam #2:** new question set, 65 questions / **170 minutes**, real conditions
   (same rules as 5.3). Score **by domain**. RCA every miss into the same table.
2. **Close the gaps** from #2 using the 6.1 rebuild loop *before* sitting #3 — don't
   take #3 cold.
3. **Exam #3:** another fresh set, same conditions. This is your readiness verdict.

### The readiness gate · D6.3
Book the real exam only when **all** of these hold (see `answers/phase-6-answers.md`
→ **D6.3** for the rationale):
- **≥ 85% overall** on two *different* recent question sets, and
- **no single domain below ~75%**, and
- misses are now mostly **"misread/time"** (test-craft), not **"didn't know"**
  (knowledge), and
- you finished each exam with **time to spare** (pacing is solved).

If any fails, you have a *specific* next action (which domain, knowledge vs craft) —
not "study more."

### Self-check · C-readiness
- Can you teach each Phase 1–5 Break/Fix out loud, from memory, in two sentences?
- For a random policy-JSON question, can you reach the answer by **elimination via
  the eval-order rule** rather than gut feel?

→ Reference: `answers/phase-6-answers.md` → **B6.3 / D6.3**.

---

## Phase 6 teardown

Nothing this phase creates needs teardown (read-only tools). But this is the **end of
the course**, so do the global sweep one last time:

- [ ] Confirm every billable thing from Phases 1–5 is torn down (GuardDuty, Config,
      Inspector, Security Hub, Detective, WAF, ALB, extra CloudTrail trails, Athena
      results bucket, SCPs detached). Run
      `python scripts/phase-1/teardown_check.py --profile scs-member` and the
      per-phase teardowns you haven't already run.
- [ ] Re-check `cost-safety.md`'s budget alarm is still active until you're sure
      everything is off.

## What you should now be able to answer cold

Pure self-test — answers in `answers/phase-6-answers.md` → **Answer-cold**.

- **C6.1** The IAM eval-order, in one line: how do SCP, identity policy, resource
  policy, permission boundary, and explicit deny combine to a final allow/deny?
- **C6.2** What three things does the Policy Simulator return, and which policy type
  does it **not** evaluate?
- **C6.3** How do you turn an `AccessDenied`'s encoded authorization message into the
  exact failing statement?
- **C6.4** "Implicit deny" vs "explicit deny" — define each and give the error-string
  tell for each.
- **C6.5** What is the passing scaled score, and what's your personal readiness gate
  before booking?

When you can answer those without notes — and you've cleared the readiness gate —
**book the exam.** That's the whole course.
