# THREADZERO Security DSL — reference

Comments start with `#` or `//`. Names are `[A-Za-z_][A-Za-z0-9_]*`. Statements end with `;` or a `{ … }` block of `key: value;` properties.
Values: identifiers, `"strings"`, integers, durations (`90d`, `12h`), times (`09:00`), `true|false`, lists `[a, b]`.

| Declaration | Form |
|---|---|
| project | `project "Name" version "1.0.0" timezone "Asia/Baku";` |
| import | `import "lib/common.tz";` — resolved by the Python loader; diagnostics map back to the imported file |
| classification | `classification MedicalRecord rank 4 extends Personal;` — builtin: Public 0, Internal 1, Confidential 2, Restricted 3, Financial 3, Personal 3, HighlySensitive 4, Credential 5, Secret 5 |
| zone | `zone Backend trust 3 kind Backend max_class Restricted;` — kinds: PublicInternet, Browser, MobileClient, InternalNetwork, ServiceMesh, Backend, DatabaseZone, AdminZone, PartnerZone, ThirdPartyZone, SecureProcessingZone, SecretZone, UntrustedZone, Custom |
| role / env / action / location | `role Support;` `env prod;` `action Approve;` `location Office;` |
| data | `data Card class Financial { owner; zones; operations; retention: 90d; encryption; logging: allowed|redacted|forbidden; export: allow|approval|deny; derived_from: [X]; }` |
| nodes | `user identity device application service api database queue filestore cloud secret external agent approval` → `service Pay in Backend { controls: [...]; egress_controls: [...]; clearance: Restricted; }` |
| assign | `assign Alice role Support;` |
| window | `window Hours { days: weekdays; from: 09:00; to: 17:00; kind: open|maintenance|emergency; tz: "Asia/Baku"; }` |
| flow | `flow F from A to B carries D1, D2 op Write { channel: tls|mtls|plain|internal; controls: [...]; step: 1; version: 2; }` |
| boundary | `boundary Browser -> Backend { require: [rate_limit]; exempt: [audit]; }` |
| policy | `policy P version "1" priority 100 scope global|zone Z|data D|resource N extends Q { rule R: effect when EXPR reason "…" obligations [audit] priority 5; }` |
| declassify | `declassify X { data: Card; produces: CardToken; via: Tokenizer; approval: RiskOfficer; }` |
| delegate | `delegate D { from: Alice; to: Bob; role: Support; expires: "2026-12-31"; chain_max: 2; revoked: false; }` |
| separation | `separation S { roles: [Author, Approver]; }` |
| workflow | `workflow W { steps: [FlowA]; approvals: [RiskOfficer]; }` |
| property | `property Confidentiality on|off;` — Confidentiality, Integrity, Authenticity, LeastPrivilege, SeparationOfDuties, Traceability, DataMinimization, BoundaryEnforcement |
| assert | `never data D enters zone Z` · `A must_not Write B` · `action Export must audit` · `N must_have authentication` · `flow F must secure_channel` · `all flows must secure_channel` · `never data D op Log` · `never class Secret op Log` · `request EXPR must deny|allow` |
| constraint | `max_class Z C` · `no_flow ZA ZB [carrying D]` · `require_control C on ZA -> ZB` · `max_fanout D n` · `acyclic_policies` |
| template | `template T(N) { service N in Backend; }` … `apply T(Worker);` (bounded depth, token level) |

## Policy expressions

Attributes: `subject`, `subject.role`, `subject.zone`, `subject.mfa`, `subject.device_trust`, `subject.clearance`, `resource`, `resource.kind`, `resource.zone`, `action`, `data`,
`data.classification`, `zone`, `zone.trust`, `zone.kind`, `env`, `context.location`, `context.time`, `context.approved`, `context.emergency`, `context.secure_channel`, `context.tenant_match`.
Operators: `== != >= <= > <`, `in [a, b]`, `and or not`, parentheses, `in_window(WindowName)`. Attribute-to-attribute comparison is allowed for ordered types
(`subject.clearance >= data.classification`). Expressions are type-checked (TZ2001 undefined entity, TZ2003 type mismatch).

Effects: `allow deny require_mfa require_approval redact encrypt audit rate_limit tokenize quarantine require_trusted_zone`.

**Precedence:** priority ↓, scope specificity ↓ (global < zone < data < resource), deny before allow, declaration order. The first terminal (allow/deny) match wins; no match = deny.
`require_trusted_zone`, `require_mfa`, `require_approval` and `quarantine` turn an `allow` into a deny / challenge / pending-approval / quarantine; other effects are obligations.

## Diagnostic codes

TZ1001 lexical · TZ1002 syntax · TZ11xx templates · TZ2001 undefined entity · TZ2002 duplicate · TZ2003 type mismatch · TZ2004 invalid flow · TZ2005 impossible permission ·
TZ2006 trust-boundary violation · TZ2007 circular policy dependency · TZ2008 unsatisfied constraint · TZ2009 classification mismatch · TZ2011 secret in model ·
TZ2012 declassification without approval · TZ4xx optimization suggestions · TZR-* security findings.
