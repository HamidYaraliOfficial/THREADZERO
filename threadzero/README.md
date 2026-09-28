<div align="center">

# 🛡️ THREADZERO

### Trust-Boundary Compiler · کامپایلر مرز اعتماد · 信任边界编译器

**Security as Compilable Architecture** — model your architecture, compile it into verified, executable security.

[English](#-english) · [فارسی](#-فارسی) · [中文](#-中文)

</div>

---

<a id="-english"></a>

# 🇬🇧 English

## Overview

**THREADZERO** is an *executable security-architecture compiler*. You describe users, services, data, trust zones, flows and policies in a small typed DSL;
THREADZERO parses it, type-checks it, proves what it can, finds exposure paths, proposes verified refactorings and **compiles the result into WebAssembly guards**
that enforce the policy at runtime — with tests generated automatically from the rules.

| Layer | Technology | Responsibility |
|---|---|---|
| **Formal core** | **Haskell** | Typed DSL, Security AST, semantic analysis, type system, finite-domain constraint solver (SMT-LIB adapter), graph verification, policy precedence & conflicts, classification propagation, refactoring engine |
| **Orchestration** | **Python** (FastAPI, wasmtime) | Project loader (imports), code generation, WASM runtime host, registry, signing, canary/rollback, test runner, reports, CI, Git adapters, AI tools |
| **Enforcement target** | **WebAssembly** | Sandboxed, deterministic policy execution in backends, gateways, edge, serverless and browsers |
| **Studio** | **TypeScript · Next.js · React · Tailwind** | Windows 11 style IDE in English, Persian (RTL) and Chinese |

## Highlights

- **Typed Security DSL** — zones, data classifications, identities, services, APIs, databases, queues, secrets, AI agents, human-approval points, flows, RBAC+ABAC policies, assertions, constraints, templates, imports, versioning.
- **Semantic analyzer** with exact `file:line:column` diagnostics: undefined entity, invalid flow, impossible permission, trust-boundary violation, circular policy dependency, unsatisfied constraint, classification mismatch, missing control.
- **Graph security analyzer** — trust-boundary violations, sensitive-data escape, excessive privilege, direct database access, missing authentication/authorization/audit, unsafe fan-out, unvalidated input paths, secret exposure, uncontrolled third-party flows, policy conflicts. Every finding has severity, evidence, graph path, violated rule, suggested fix and confidence.
- **Policy compiler** → WASM guard, JSON artifact, **Rego**, HTTP middleware, gRPC interceptor, queue/storage/workflow guards and a TypeScript/JavaScript wrapper — all checked to behave identically.
- **Security refactoring engine** — graph transformations (gateway → policy enforcement → sanitizer, tokenization layer, repository service, approval boundary, service split, broker…) with preconditions, postconditions, security & functional impact, cost and residual risk. Nothing is ever applied automatically.
- **Simulation studios** for policies and boundary crossings, a WASM runtime lab, performance/scale lab, fault-injection lab and canary/rollback host.
- **Reproducible builds** — lockfile, deterministic artifacts, Ed25519-signed packages, tamper-evident decision log.
- **Access windows** — opening hours, maintenance and emergency windows that you enter yourself; THREADZERO tells you whether a window is open *right now*, how long until it closes/opens, and compiles the windows into the WASM policy.
- **Defensive by design** — secret values can never enter the model, every runtime failure fails closed, the AI assistant can only propose verified changes.

## Requirements

| Tool | Version | Needed for |
|---|---|---|
| Python | 3.10 – 3.13 | compiler orchestration, API, CLI |
| GHC (Glasgow Haskell Compiler) | 9.4 or newer | building the Haskell core (only GHC boot libraries — no Hackage download) |
| Node.js | 18 or newer | building the web studio (optional; the CLI works without it) |
| OPA, z3 | any | *optional*: Rego differential tests, external SMT solving |

## Installation

### Linux · macOS · WSL

```bash
# 1) prerequisites (Debian/Ubuntu example)
sudo apt update && sudo apt install -y python3 python3-pip python3-venv ghc nodejs npm

# 2) one-shot installer: Python packages + Haskell core + web studio
./install.sh
```

Manual equivalent:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt            # wasmtime, fastapi, uvicorn, cryptography, PyYAML, pytest, httpx
pip install -e .                           # installs the `threadzero` command
make core                                  # ghc -O1 … -o haskell/build/threadzero-core
cd web && npm install && npm run build     # static web studio (web/out)
```

### Windows 10 / 11 (PowerShell)

```powershell
winget install Python.Python.3.12
winget install OpenJS.NodeJS.LTS
# GHC through GHCup (installs ghc + cabal)
Set-ExecutionPolicy Bypass -Scope Process -Force
Invoke-Command -ScriptBlock ([ScriptBlock]::Create((Invoke-WebRequest https://www.haskell.org/ghcup/sh/bootstrap-haskell.ps1 -UseBasicParsing))) -ArgumentList $true

# one-shot installer (or double-click install.bat)
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Manual equivalent:

```powershell
python -m pip install -r requirements.txt
python -m pip install -e .
mkdir haskell\build
ghc -O1 -ihaskell/src -ihaskell/app -outputdir haskell/build -o haskell/build/threadzero-core.exe haskell/app/Main.hs
cd web; npm install; npm run build
```

### Verify the installation

```bash
threadzero doctor          # checks the Haskell core, wasmtime, FastAPI, node, opa, z3
make test                  # Haskell property tests + Python test-suite
```

## Quick start

```bash
threadzero serve                                   # API + web studio → http://127.0.0.1:8737
threadzero check    examples/secure_api/main.tz    # diagnostics + findings
threadzero verify   examples/secure_api/main.tz    # properties, assertions, constraints
threadzero compile  examples/secure_api/main.tz -o generated/   # WASM, Rego, JS/TS, guards, signed package
threadzero simulate examples/secure_api/main.tz '{"subject":{"roles":["Support"],"mfa":true},"data":"Profile","action":"Read","zone":"Backend","context":{"time":600}}'
threadzero refactor examples/secure_api/main.tz --finding F-001
threadzero schedule examples/secure_api/main.tz --now 2026-09-21T08:30:00     # open now? next change?
threadzero ci       examples/secure_api/main.tz --fail-on high --sarif out.sarif
```

Web studio in development mode (hot reload, API on port 8737):

```bash
threadzero serve &                                  # terminal 1
cd web && NEXT_PUBLIC_API=http://127.0.0.1:8737 npm run dev    # terminal 2 → http://localhost:3000
```

## The DSL in 30 seconds

```
project "Payments" version "1.0.0" timezone "UTC";

zone Browser  trust 1 kind Browser  max_class Financial;
zone Backend  trust 3 kind Backend;
zone Secure   trust 4 kind SecureProcessingZone;

role Shopper;   role Finance;
window BusinessHours { days: weekdays; from: 08:00; to: 18:00; kind: open; }

data Card class Financial { zones: [Browser, Secure]; operations: [Create, Transform]; export: deny; logging: forbidden; }

application Checkout in Browser { controls: [encryption]; }
service Tokenizer in Secure { controls: [authentication, authorization, audit, isolation, schema_validation, input_validation, rate_limit]; }

flow TokenizeCard from Checkout to Tokenizer carries Card op Transform { channel: tls; }

policy CardRules priority 900 scope global {
  rule CardOnlyInSecureZone: deny when data == Card and not (zone.kind in [SecureProcessingZone, Browser]) reason "cards stay in the secure zone";
  rule FinanceRefund: allow when subject.role == Finance and subject.mfa and in_window(BusinessHours) obligations [audit];
  rule ApprovalForExport: require_approval when action == Export and data.classification >= Confidential;
}

assert CardNeverExported: request data == Card and action == Export must deny;
```

Full reference: [`docs/DSL_REFERENCE.md`](docs/DSL_REFERENCE.md) · architecture notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Web studio

A Windows 11 (Fluent) style workspace with a title bar, navigation view, command palette (`Ctrl+K`), resizable panels, diagnostics and a live compile status bar.

| Group | Pages |
|---|---|
| Design | Architecture Studio · DSL Editor (+ Compiler Playground) · Trust Boundary Canvas (2D React Flow + 3D) · Data Flow Explorer · Policy Studio (+ Policy Inspector, Permission Explorer) · **Access Windows** |
| Analyze | Compiler Console · Security Findings · Refactoring Lab (current + 3 candidates, diffs, scorecard) · Dependency Graph · Change Impact · AI Assistant |
| Runtime | Policy Simulator (+ Boundary Simulation Studio) · WASM Runtime Lab (browser sandbox, benchmarks, faults, canary/rollback) · Test Lab |
| Ship | Artifact Registry · CI Integration · Reports (Markdown, JSON, YAML, HTML, print-to-PDF, compliance mapping) |
| Manage | Administration · Settings |

**Themes:** Windows default (follows the OS), Light, Dark, AMOLED, **Red**, **Blue**.
**Languages:** English (LTR) · فارسی (**RTL** layout) · 中文 (LTR). Code editors and diagrams always stay left-to-right so code remains readable in the Persian UI.

## Access windows (opening hours)

Open **Access Windows** and add windows yourself: name, type (opening hours / maintenance / emergency), days, opening and closing time and time zone.
For each window THREADZERO shows the current time in that zone, whether it is **open now**, a live countdown to the **next opening or closing**, the next opening date and how long it stays open.
You can simulate any other moment, save the schedule on the server, or insert the windows into your DSL — policies then use `in_window(Name)` and the compiled WASM guard enforces them.

## What `compile` produces

| File | Purpose |
|---|---|
| `policy.wasm`, `policy.wat` | sandboxed guard — exports `authorize`, `validate_flow`, `validate_boundary`, `inspect_context`, `classify_data`, `audit_event`, `deny_reason` |
| `policy.json` | JSON policy artifact (rules, symbol tables, ABI) |
| `policy.rego` | Rego-compatible policy (verified against OPA) |
| `guard.js`, `guard.ts` | JavaScript / TypeScript validation wrapper (Node, browsers, edge) |
| `guards/*` | ASGI/Express middleware, gRPC interceptor, queue/storage/workflow guards, route tables |
| `tests/*` | generated positive, negative, boundary, context and assertion tests |
| `manifest.json`, `SIGNATURE.json`, `*.tzpkg` | reproducible, versioned, Ed25519-signed package |

## Tests

```bash
make test-haskell   # 55 tests: property-based, parser, type system, solver, conflicts, graph, refactoring equivalence, determinism, fuzzing
make test-python    # 90+ tests: golden artifacts, WASM == reference == JS == Rego, signing, canary/rollback, fault injection, API, CLI
make test-web       # renders all 20 views in EN/FA/ZH against a live backend
```

## Project layout

```
haskell/    formal core (src/TZ/*.hs · app/Main.hs · test/Spec.hs)
python/     threadzero package (core bridge, codegen, runtime, host, testing, api, cli) + tests
web/        Next.js studio (app/, components/, views/, lib/) — `npm run build` → web/out
examples/   secure_api · payment_workflow · document_pipeline · ai_agent_access · multi_tenant_saas · partner_integration · diagnostics_demo
docs/       DSL reference · architecture
```

## Security notes

THREADZERO is a **defensive** tool. It analyses your own architecture models, never generates exploits, and contains no mechanism to bypass controls.
Secret values must never appear in a model (only references), generated modules import nothing from the host, and any runtime failure ends in *deny*.
Compliance mappings are evidence only — they are not a statement of compliance.

## License

MIT — see [`LICENSE`](LICENSE).

---

<a id="-فارسی"></a>

<div dir="rtl" align="right">

# 🇮🇷 فارسی

## معرفی

**THREADZERO** یک «کامپایلر اجرایی معماری امنیت» است. کاربران، سرویس‌ها، داده‌ها، نواحی اعتماد، جریان‌ها و سیاست‌ها را در یک DSL کوچکِ تایپ‌دار می‌نویسید؛
THREADZERO آن را تجزیه و نوع‌سنجی می‌کند، هرچه قابل اثبات باشد اثبات می‌کند، مسیرهای افشا را پیدا می‌کند، بازسازی‌های تأییدشده پیشنهاد می‌دهد و در نهایت
**نگهبان‌های WebAssembly** تولید می‌کند که سیاست را در زمان اجرا اعمال می‌کنند — همراه با تست‌هایی که خودکار از روی قوانین ساخته می‌شوند.

| لایه | فناوری | مسئولیت |
|---|---|---|
| **هستهٔ صوری** | **Haskell** | DSL تایپ‌دار، AST امنیتی، تحلیل معنایی، سیستم نوع، حل‌کنندهٔ قیدهای دامنه‌متناهی (آداپتور SMT-LIB)، راستی‌آزمایی گراف، تقدم و تعارض سیاست‌ها، انتشار طبقه‌بندی داده، موتور بازسازی |
| **هماهنگ‌سازی** | **Python** (‏FastAPI، wasmtime) | بارگذاری پروژه (import)، تولید کد، میزبان زمان اجرای WASM، مخزن آرتیفکت، امضا، قناری/بازگشت، اجرای تست، گزارش، CI، آداپتور Git، ابزارهای هوش مصنوعی |
| **هدف اجرا** | **WebAssembly** | اجرای ایزوله و قطعی سیاست در بک‌اند، درگاه، لبه، سرورلس و مرورگر |
| **استودیو** | **TypeScript · Next.js · React · Tailwind** | محیط گرافیکی به سبک ویندوز ۱۱ به سه زبان انگلیسی، فارسی (راست‌به‌چپ) و چینی |

## ویژگی‌های کلیدی

- **DSL امنیتی تایپ‌دار** — نواحی، طبقه‌بندی داده، هویت‌ها، سرویس‌ها، API، پایگاه داده، صف، رمزینه‌ها، عامل‌های هوش مصنوعی، نقاط تأیید انسانی، جریان‌ها، سیاست‌های RBAC+ABAC، ادعاها، قیدها، قالب‌ها، import و نسخه‌بندی.
- **تحلیلگر معنایی** با خطاهای دقیق `فایل:خط:ستون`: موجودیت تعریف‌نشده، جریان نامعتبر، مجوز ناممکن، نقض مرز اعتماد، وابستگی چرخه‌ای سیاست، قید ارضانشده، ناسازگاری طبقه‌بندی و کنترل گمشده.
- **تحلیلگر امنیتی گراف** — نقض مرز اعتماد، فرار داده حساس، دسترسی بیش‌ازحد، دسترسی مستقیم به پایگاه داده، نبود احراز هویت/مجوز/ممیزی، پخش ناایمن داده، مسیر ورودی اعتبارسنجی‌نشده، افشای رمز، جریان کنترل‌نشدهٔ شخص ثالث و تعارض سیاست. هر یافته شدت، شواهد، مسیر گراف، قانون نقض‌شده، راه‌حل پیشنهادی و میزان اطمینان دارد.
- **کامپایلر سیاست** → نگهبان WASM، آرتیفکت JSON، **Rego**، میان‌افزار HTTP، رهگیر gRPC، نگهبان صف/ذخیره‌سازی/گردش‌کار و پوشش‌دهندهٔ TypeScript/JavaScript — با بررسی رفتار یکسان همهٔ خروجی‌ها.
- **موتور بازسازی امنیتی** — تبدیل‌های گرافی (دروازه ← اعمال سیاست ← پاک‌سازی، لایهٔ توکن‌سازی، سرویس مخزن، مرز تأیید انسانی، شکافتن سرویس، کارگزار توزیع…) با پیش‌شرط، پس‌شرط، اثر امنیتی و عملکردی، هزینه و ریسک باقی‌مانده. هیچ چیز به‌صورت خودکار اعمال نمی‌شود.
- **استودیوهای شبیه‌سازی** سیاست و عبور از مرز، آزمایشگاه WASM، آزمایشگاه کارایی و مقیاس، آزمایشگاه تزریق خطا و میزبان قناری/بازگشت.
- **ساخت بازتولیدپذیر** — فایل قفل، آرتیفکت قطعی، بسته‌های امضاشدهٔ Ed25519 و گزارش تصمیم تغییرناپذیر.
- **بازه‌های دسترسی** — ساعات کاری، نگهداری و اضطراری را خودتان وارد می‌کنید؛ THREADZERO نشان می‌دهد بازه *همین حالا* باز است یا نه، تا بسته/بازشدن بعدی چقدر مانده و بازه‌ها را به سیاست WASM کامپایل می‌کند.
- **دفاعی از پایه** — مقدار رمز هرگز وارد مدل نمی‌شود، هر خطای زمان اجرا به «رد» ختم می‌شود و دستیار هوش مصنوعی فقط تغییرات تأییدشده پیشنهاد می‌دهد.

## پیش‌نیازها

| ابزار | نسخه | کاربرد |
|---|---|---|
| Python | ۳٫۱۰ تا ۳٫۱۳ | هماهنگ‌سازی کامپایلر، API، خط فرمان |
| GHC (کامپایلر Haskell) | ۹٫۴ یا بالاتر | ساخت هستهٔ Haskell (فقط کتابخانه‌های همراه GHC — بدون دانلود از Hackage) |
| Node.js | ۱۸ یا بالاتر | ساخت استودیوی وب (اختیاری؛ خط فرمان بدون آن هم کار می‌کند) |
| OPA و z3 | هر نسخه | *اختیاری*: تست تطبیقی Rego و حل‌کنندهٔ SMT بیرونی |

## نصب

### لینوکس · مک · WSL

```bash
# ۱) پیش‌نیازها (نمونهٔ دبیان/اوبونتو)
sudo apt update && sudo apt install -y python3 python3-pip python3-venv ghc nodejs npm

# ۲) نصب‌کنندهٔ یک‌مرحله‌ای: بسته‌های پایتون + هستهٔ Haskell + استودیوی وب
./install.sh
```

معادل دستی:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt            # wasmtime, fastapi, uvicorn, cryptography, PyYAML, pytest, httpx
pip install -e .                           # دستور `threadzero` را نصب می‌کند
make core                                  # ghc -O1 … -o haskell/build/threadzero-core
cd web && npm install && npm run build     # استودیوی وب ایستا (web/out)
```

### ویندوز ۱۰ / ۱۱ (پاورشل)

```powershell
winget install Python.Python.3.12
winget install OpenJS.NodeJS.LTS
# نصب GHC با GHCup (ghc و cabal را نصب می‌کند)
Set-ExecutionPolicy Bypass -Scope Process -Force
Invoke-Command -ScriptBlock ([ScriptBlock]::Create((Invoke-WebRequest https://www.haskell.org/ghcup/sh/bootstrap-haskell.ps1 -UseBasicParsing))) -ArgumentList $true

# نصب‌کنندهٔ یک‌مرحله‌ای (یا دوبار کلیک روی install.bat)
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

معادل دستی:

```powershell
python -m pip install -r requirements.txt
python -m pip install -e .
mkdir haskell\build
ghc -O1 -ihaskell/src -ihaskell/app -outputdir haskell/build -o haskell/build/threadzero-core.exe haskell/app/Main.hs
cd web; npm install; npm run build
```

### بررسی نصب

```bash
threadzero doctor          # هستهٔ Haskell، wasmtime، FastAPI، node، opa و z3 را بررسی می‌کند
make test                  # تست‌های ویژگی‌محور Haskell + مجموعه‌تست پایتون
```

## شروع سریع

```bash
threadzero serve                                   # API + استودیوی وب → http://127.0.0.1:8737
threadzero check    examples/secure_api/main.tz    # عیب‌یابی و یافته‌ها
threadzero verify   examples/secure_api/main.tz    # ویژگی‌ها، ادعاها و قیدها
threadzero compile  examples/secure_api/main.tz -o generated/   # WASM، Rego، JS/TS، نگهبان‌ها و بستهٔ امضاشده
threadzero simulate examples/secure_api/main.tz '{"subject":{"roles":["Support"],"mfa":true},"data":"Profile","action":"Read","zone":"Backend","context":{"time":600}}'
threadzero refactor examples/secure_api/main.tz --finding F-001
threadzero schedule examples/secure_api/main.tz --now 2026-09-21T08:30:00     # اکنون باز است؟ تغییر بعدی چه زمانی؟
threadzero ci       examples/secure_api/main.tz --fail-on high --sarif out.sarif
```

استودیوی وب در حالت توسعه (بارگذاری مجدد زنده، API روی پورت ۸۷۳۷):

```bash
threadzero serve &                                  # ترمینال ۱
cd web && NEXT_PUBLIC_API=http://127.0.0.1:8737 npm run dev    # ترمینال ۲ → http://localhost:3000
```

## DSL در ۳۰ ثانیه

```
project "Payments" version "1.0.0" timezone "UTC";

zone Browser  trust 1 kind Browser  max_class Financial;
zone Backend  trust 3 kind Backend;
zone Secure   trust 4 kind SecureProcessingZone;

role Shopper;   role Finance;
window BusinessHours { days: weekdays; from: 08:00; to: 18:00; kind: open; }

data Card class Financial { zones: [Browser, Secure]; operations: [Create, Transform]; export: deny; logging: forbidden; }

application Checkout in Browser { controls: [encryption]; }
service Tokenizer in Secure { controls: [authentication, authorization, audit, isolation, schema_validation, input_validation, rate_limit]; }

flow TokenizeCard from Checkout to Tokenizer carries Card op Transform { channel: tls; }

policy CardRules priority 900 scope global {
  rule CardOnlyInSecureZone: deny when data == Card and not (zone.kind in [SecureProcessingZone, Browser]) reason "cards stay in the secure zone";
  rule FinanceRefund: allow when subject.role == Finance and subject.mfa and in_window(BusinessHours) obligations [audit];
  rule ApprovalForExport: require_approval when action == Export and data.classification >= Confidential;
}

assert CardNeverExported: request data == Card and action == Export must deny;
```

مرجع کامل: [`docs/DSL_REFERENCE.md`](docs/DSL_REFERENCE.md) · یادداشت‌های معماری: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## استودیوی وب

فضای کاری به سبک ویندوز ۱۱ (Fluent) با نوار عنوان، منوی ناوبری، پالت دستورات (`Ctrl+K`)، پنل‌های قابل تغییر اندازه، عیب‌یابی و نوار وضعیت کامپایل زنده.

| گروه | صفحه‌ها |
|---|---|
| طراحی | استودیوی معماری · ویرایشگر DSL (+ زمین‌بازی کامپایلر) · بوم مرز اعتماد (دوبعدی React Flow + سه‌بعدی) · کاوشگر جریان داده · استودیوی سیاست (+ بازرس سیاست، کاوشگر دسترسی) · **بازه‌های دسترسی** |
| تحلیل | کنسول کامپایلر · یافته‌های امنیتی · آزمایشگاه بازسازی (معماری فعلی + ۳ نامزد، تفاوت‌ها، کارنامه) · گراف وابستگی · تحلیل اثر تغییر · دستیار هوشمند |
| زمان اجرا | شبیه‌ساز سیاست (+ استودیوی شبیه‌سازی مرز) · آزمایشگاه WASM (سندباکس مرورگر، بنچمارک، خطا، قناری/بازگشت) · آزمایشگاه تست |
| انتشار | مخزن آرتیفکت · یکپارچه‌سازی CI · گزارش‌ها (Markdown، JSON، YAML، HTML، چاپ به PDF، نگاشت انطباق) |
| مدیریت | مدیریت · تنظیمات |

**پوسته‌ها:** پیش‌فرض ویندوز (هماهنگ با سیستم‌عامل)، روشن، تیره، آمولد، **قرمز**، **آبی**.
**زبان‌ها:** English (چپ‌به‌راست) · فارسی (چیدمان **راست‌به‌چپ**) · 中文 (چپ‌به‌راست). ویرایشگر کد و نمودارها همیشه چپ‌به‌راست می‌مانند تا خوانایی کد در رابط فارسی حفظ شود.

## بازه‌های دسترسی (ساعات کاری)

به صفحهٔ **بازه‌های دسترسی** بروید و بازه‌ها را خودتان اضافه کنید: نام، نوع (ساعات کاری / نگهداری / اضطراری)، روزها، ساعت شروع و پایان و منطقهٔ زمانی.
برای هر بازه، THREADZERO زمان فعلی همان منطقه، وضعیت **اکنون باز است یا نه**، شمارندهٔ زندهٔ **باز/بسته‌شدن بعدی**، تاریخ بازشدن بعدی و مدت باز ماندن را نشان می‌دهد.
می‌توانید هر لحظهٔ دیگری را شبیه‌سازی کنید، برنامه را روی سرور ذخیره کنید یا بازه‌ها را در DSL درج کنید — سیاست‌ها با `in_window(Name)` از آن‌ها استفاده می‌کنند و نگهبان WASM آن را اعمال می‌کند.

## خروجی دستور `compile`

| فایل | کاربرد |
|---|---|
| `policy.wasm`، `policy.wat` | نگهبان ایزوله — توابع `authorize`، `validate_flow`، `validate_boundary`، `inspect_context`، `classify_data`، `audit_event`، `deny_reason` |
| `policy.json` | آرتیفکت سیاست به‌صورت JSON (قوانین، جدول نمادها، ABI) |
| `policy.rego` | سیاست سازگار با Rego (راستی‌آزمایی‌شده با OPA) |
| `guard.js`، `guard.ts` | پوشش‌دهندهٔ اعتبارسنجی JavaScript / TypeScript (Node، مرورگر، لبه) |
| `guards/*` | میان‌افزار ASGI/Express، رهگیر gRPC، نگهبان صف/ذخیره‌سازی/گردش‌کار، جدول مسیرها |
| `tests/*` | تست‌های تولیدشدهٔ مثبت، منفی، مرزی، زمینه‌ای و ادعا |
| `manifest.json`، `SIGNATURE.json`، `*.tzpkg` | بستهٔ بازتولیدپذیر، نسخه‌دار و امضاشده با Ed25519 |

## تست‌ها

```bash
make test-haskell   # ۵۵ تست: ویژگی‌محور، تجزیه‌گر، سیستم نوع، حل‌کننده، تعارض، گراف، هم‌ارزی بازسازی، قطعیت، فازینگ
make test-python    # بیش از ۹۰ تست: آرتیفکت طلایی، WASM == مرجع == JS == Rego، امضا، قناری/بازگشت، تزریق خطا، API، CLI
make test-web       # هر ۲۰ صفحه را در EN/FA/ZH روی یک بک‌اند زنده رندر می‌کند
```

## ساختار پروژه

```
haskell/    هستهٔ صوری (src/TZ/*.hs · app/Main.hs · test/Spec.hs)
python/     بستهٔ threadzero (پل هسته، تولید کد، زمان اجرا، میزبان، تست، api، cli) + تست‌ها
web/        استودیوی Next.js (app/، components/، views/، lib/) — دستور `npm run build` → web/out
examples/   secure_api · payment_workflow · document_pipeline · ai_agent_access · multi_tenant_saas · partner_integration · diagnostics_demo
docs/       مرجع DSL · معماری
```

## نکات امنیتی

THREADZERO ابزاری **دفاعی** است. فقط مدل‌های معماریِ خودتان را تحلیل می‌کند، هرگز اکسپلویت تولید نمی‌کند و هیچ سازوکاری برای دور زدن کنترل‌ها ندارد.
مقدار رمز هرگز نباید در مدل بیاید (فقط ارجاع)، ماژول‌های تولیدشده هیچ چیزی از میزبان وارد نمی‌کنند و هر خطای زمان اجرا به *رد* ختم می‌شود.
نگاشت انطباق فقط شاهد است و اعلام انطباق نیست.

## مجوز

MIT — فایل [`LICENSE`](LICENSE) را ببینید.

</div>

---

<a id="-中文"></a>

# 🇨🇳 中文

## 简介

**THREADZERO** 是一个“可执行的安全架构编译器”。你用一门小巧的强类型 DSL 描述用户、服务、数据、信任区域、数据流与策略；
THREADZERO 会解析并做类型检查，尽可能给出证明，发现暴露路径，提出经过验证的重构方案，并把结果**编译成 WebAssembly 守卫**，在运行时强制执行策略——同时根据规则自动生成测试。

| 层 | 技术 | 职责 |
|---|---|---|
| **形式化内核** | **Haskell** | 强类型 DSL、安全 AST、语义分析、类型系统、有限域约束求解器（SMT-LIB 适配器）、图验证、策略优先级与冲突、数据分类传播、重构引擎 |
| **编排层** | **Python**（FastAPI、wasmtime） | 项目加载（import）、代码生成、WASM 运行时宿主、制品注册表、签名、金丝雀/回滚、测试执行、报告、CI、Git 适配器、AI 工具 |
| **执行目标** | **WebAssembly** | 在后端、网关、边缘、Serverless 与浏览器中以沙箱方式确定性地执行策略 |
| **工作室** | **TypeScript · Next.js · React · Tailwind** | Windows 11 风格的图形界面，支持英文、波斯文（从右到左）与中文 |

## 核心特性

- **强类型安全 DSL**——区域、数据分类、身份、服务、API、数据库、队列、密钥、AI 代理、人工审批点、数据流、RBAC+ABAC 策略、断言、约束、模板、import 与版本管理。
- **语义分析器**，诊断精确到 `文件:行:列`：未定义实体、无效数据流、不可能的权限、信任边界违规、策略循环依赖、未满足的约束、分类不一致、缺失控制措施。
- **图安全分析器**——信任边界违规、敏感数据逃逸、权限过大、直接访问数据库、缺失认证/授权/审计、不安全的数据扇出、未校验的输入路径、密钥暴露、不受控的第三方数据流、策略冲突。每条发现都包含严重程度、证据、图路径、违反的规则、修复建议与置信度。
- **策略编译器** → WASM 守卫、JSON 制品、**Rego**、HTTP 中间件、gRPC 拦截器、队列/存储/工作流守卫以及 TypeScript/JavaScript 封装——并验证各输出行为一致。
- **安全重构引擎**——图变换（网关 → 策略执行 → 净化、令牌化层、仓储服务、人工审批边界、服务拆分、分发代理…），带前置条件、后置条件、安全与功能影响、成本与残余风险。任何变更都不会被自动应用。
- **模拟工作室**（策略与边界穿越）、WASM 运行时实验室、性能/规模实验室、故障注入实验室以及金丝雀/回滚宿主。
- **可复现构建**——锁文件、确定性制品、Ed25519 签名包、防篡改的决策日志。
- **访问时段**——营业时间、维护窗口与紧急窗口由你自己输入；THREADZERO 会告诉你某个时段*此刻*是否开放、距离关闭/开放还有多久，并把时段编译进 WASM 策略。
- **天生防御**——密钥值永远无法进入模型，任何运行时故障都会“默认拒绝”，AI 助手只能提出经过验证的方案。

## 环境要求

| 工具 | 版本 | 用途 |
|---|---|---|
| Python | 3.10 – 3.13 | 编译器编排、API、命令行 |
| GHC（Glasgow Haskell 编译器） | 9.4 或更高 | 构建 Haskell 内核（仅使用 GHC 自带库，无需从 Hackage 下载） |
| Node.js | 18 或更高 | 构建 Web 工作室（可选；命令行不依赖它） |
| OPA、z3 | 任意版本 | *可选*：Rego 差分测试、外部 SMT 求解 |

## 安装

### Linux · macOS · WSL

```bash
# 1) 先决条件（以 Debian/Ubuntu 为例）
sudo apt update && sudo apt install -y python3 python3-pip python3-venv ghc nodejs npm

# 2) 一键安装：Python 依赖 + Haskell 内核 + Web 工作室
./install.sh
```

等价的手动步骤：

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt            # wasmtime, fastapi, uvicorn, cryptography, PyYAML, pytest, httpx
pip install -e .                           # 安装 `threadzero` 命令
make core                                  # ghc -O1 … -o haskell/build/threadzero-core
cd web && npm install && npm run build     # 静态 Web 工作室 (web/out)
```

### Windows 10 / 11（PowerShell）

```powershell
winget install Python.Python.3.12
winget install OpenJS.NodeJS.LTS
# 通过 GHCup 安装 GHC（同时安装 ghc 与 cabal）
Set-ExecutionPolicy Bypass -Scope Process -Force
Invoke-Command -ScriptBlock ([ScriptBlock]::Create((Invoke-WebRequest https://www.haskell.org/ghcup/sh/bootstrap-haskell.ps1 -UseBasicParsing))) -ArgumentList $true

# 一键安装（或双击 install.bat）
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

等价的手动步骤：

```powershell
python -m pip install -r requirements.txt
python -m pip install -e .
mkdir haskell\build
ghc -O1 -ihaskell/src -ihaskell/app -outputdir haskell/build -o haskell/build/threadzero-core.exe haskell/app/Main.hs
cd web; npm install; npm run build
```

### 验证安装

```bash
threadzero doctor          # 检查 Haskell 内核、wasmtime、FastAPI、node、opa、z3
make test                  # Haskell 属性测试 + Python 测试套件
```

## 快速开始

```bash
threadzero serve                                   # API + Web 工作室 → http://127.0.0.1:8737
threadzero check    examples/secure_api/main.tz    # 诊断与发现
threadzero verify   examples/secure_api/main.tz    # 属性、断言与约束
threadzero compile  examples/secure_api/main.tz -o generated/   # WASM、Rego、JS/TS、守卫与签名包
threadzero simulate examples/secure_api/main.tz '{"subject":{"roles":["Support"],"mfa":true},"data":"Profile","action":"Read","zone":"Backend","context":{"time":600}}'
threadzero refactor examples/secure_api/main.tz --finding F-001
threadzero schedule examples/secure_api/main.tz --now 2026-09-21T08:30:00     # 现在开放吗？下一次变化是什么时候？
threadzero ci       examples/secure_api/main.tz --fail-on high --sarif out.sarif
```

开发模式下运行 Web 工作室（热重载，API 位于 8737 端口）：

```bash
threadzero serve &                                  # 终端 1
cd web && NEXT_PUBLIC_API=http://127.0.0.1:8737 npm run dev    # 终端 2 → http://localhost:3000
```

## 30 秒了解 DSL

```
project "Payments" version "1.0.0" timezone "UTC";

zone Browser  trust 1 kind Browser  max_class Financial;
zone Backend  trust 3 kind Backend;
zone Secure   trust 4 kind SecureProcessingZone;

role Shopper;   role Finance;
window BusinessHours { days: weekdays; from: 08:00; to: 18:00; kind: open; }

data Card class Financial { zones: [Browser, Secure]; operations: [Create, Transform]; export: deny; logging: forbidden; }

application Checkout in Browser { controls: [encryption]; }
service Tokenizer in Secure { controls: [authentication, authorization, audit, isolation, schema_validation, input_validation, rate_limit]; }

flow TokenizeCard from Checkout to Tokenizer carries Card op Transform { channel: tls; }

policy CardRules priority 900 scope global {
  rule CardOnlyInSecureZone: deny when data == Card and not (zone.kind in [SecureProcessingZone, Browser]) reason "cards stay in the secure zone";
  rule FinanceRefund: allow when subject.role == Finance and subject.mfa and in_window(BusinessHours) obligations [audit];
  rule ApprovalForExport: require_approval when action == Export and data.classification >= Confidential;
}

assert CardNeverExported: request data == Card and action == Export must deny;
```

完整参考：[`docs/DSL_REFERENCE.md`](docs/DSL_REFERENCE.md) · 架构说明：[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Web 工作室

Windows 11（Fluent）风格的工作区：标题栏、导航视图、命令面板（`Ctrl+K`）、可调整大小的面板、诊断面板与实时编译状态栏。

| 分组 | 页面 |
|---|---|
| 设计 | 架构工作室 · DSL 编辑器（+ 编译器演练场）· 信任边界画布（2D React Flow + 3D）· 数据流浏览器 · 策略工作室（+ 策略检查器、权限浏览器）· **访问时段** |
| 分析 | 编译器控制台 · 安全发现 · 重构实验室（当前架构 + 3 个候选、差异、记分卡）· 依赖图 · 变更影响 · AI 助手 |
| 运行时 | 策略模拟器（+ 边界模拟工作室）· WASM 运行时实验室（浏览器沙箱、基准测试、故障、金丝雀/回滚）· 测试实验室 |
| 发布 | 制品注册表 · CI 集成 · 报告（Markdown、JSON、YAML、HTML、打印为 PDF、合规映射） |
| 管理 | 管理 · 设置 |

**主题：** Windows 默认（跟随系统）、浅色、深色、AMOLED、**红色**、**蓝色**。
**语言：** English（从左到右）· فارسی（**从右到左**布局）· 中文（从左到右）。代码编辑器与图表始终保持从左到右，因此在波斯语界面中代码依然清晰易读。

## 访问时段（营业时间）

打开**访问时段**页面，自己添加时段：名称、类型（营业时间 / 维护 / 紧急）、星期、开始与结束时间以及时区。
对每个时段，THREADZERO 会显示该时区的当前时间、**此刻是否开放**、距离**下一次开放或关闭**的实时倒计时、下次开放的日期以及持续开放的时长。
你可以模拟任意其他时刻、把时间表保存到服务器，或把时段插入 DSL——策略通过 `in_window(Name)` 使用它们，编译出的 WASM 守卫负责强制执行。

## `compile` 的产物

| 文件 | 用途 |
|---|---|
| `policy.wasm`、`policy.wat` | 沙箱守卫——导出 `authorize`、`validate_flow`、`validate_boundary`、`inspect_context`、`classify_data`、`audit_event`、`deny_reason` |
| `policy.json` | JSON 策略制品（规则、符号表、ABI） |
| `policy.rego` | 兼容 Rego 的策略（已用 OPA 验证） |
| `guard.js`、`guard.ts` | JavaScript / TypeScript 校验封装（Node、浏览器、边缘） |
| `guards/*` | ASGI/Express 中间件、gRPC 拦截器、队列/存储/工作流守卫、路由表 |
| `tests/*` | 自动生成的正向、反向、边界、上下文与断言测试 |
| `manifest.json`、`SIGNATURE.json`、`*.tzpkg` | 可复现、带版本、经 Ed25519 签名的包 |

## 测试

```bash
make test-haskell   # 55 项测试：属性测试、解析器、类型系统、求解器、冲突、图、重构等价性、确定性、模糊测试
make test-python    # 90+ 项测试：黄金制品、WASM == 参考实现 == JS == Rego、签名、金丝雀/回滚、故障注入、API、CLI
make test-web       # 在实时后端上以 EN/FA/ZH 渲染全部 20 个页面
```

## 项目结构

```
haskell/    形式化内核 (src/TZ/*.hs · app/Main.hs · test/Spec.hs)
python/     threadzero 包（内核桥接、代码生成、运行时、宿主、测试、api、cli）+ 测试
web/        Next.js 工作室 (app/、components/、views/、lib/) — `npm run build` → web/out
examples/   secure_api · payment_workflow · document_pipeline · ai_agent_access · multi_tenant_saas · partner_integration · diagnostics_demo
docs/       DSL 参考 · 架构说明
```

## 安全说明

THREADZERO 是一个**防御性**工具：它只分析你自己的架构模型，从不生成漏洞利用代码，也不包含任何绕过控制措施的机制。
密钥值绝不能出现在模型中（只保留引用），生成的模块不会从宿主导入任何能力，任何运行时故障都会以*拒绝*收场。
合规映射仅作为证据，并不代表已经合规。

## 许可证

MIT — 见 [`LICENSE`](LICENSE)。
