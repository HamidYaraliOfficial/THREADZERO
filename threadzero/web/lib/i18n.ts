export type Lang = 'en' | 'fa' | 'zh';
export const LANGS: { id: Lang; label: string; dir: 'ltr' | 'rtl' }[] = [
  { id: 'en', label: 'English', dir: 'ltr' },
  { id: 'fa', label: 'فارسی', dir: 'rtl' },
  { id: 'zh', label: '中文', dir: 'ltr' },
];

const en = {
  appName: 'THREADZERO', appTagline: 'Trust-Boundary Compiler',
  // navigation
  'nav.studio': 'Architecture Studio', 'nav.editor': 'DSL Editor', 'nav.canvas': 'Trust Boundary Canvas', 'nav.flows': 'Data Flow Explorer',
  'nav.policies': 'Policy Studio', 'nav.console': 'Compiler Console', 'nav.findings': 'Security Findings', 'nav.refactor': 'Refactoring Lab',
  'nav.simulator': 'Policy Simulator', 'nav.wasm': 'WASM Runtime Lab', 'nav.tests': 'Test Lab', 'nav.dependencies': 'Dependency Graph',
  'nav.impact': 'Change Impact', 'nav.registry': 'Artifact Registry', 'nav.ci': 'CI Integration', 'nav.reports': 'Reports',
  'nav.schedule': 'Access Windows', 'nav.assistant': 'AI Assistant', 'nav.admin': 'Administration', 'nav.settings': 'Settings',
  'nav.group.design': 'Design', 'nav.group.analyze': 'Analyze', 'nav.group.runtime': 'Runtime', 'nav.group.ship': 'Ship', 'nav.group.manage': 'Manage',
  // common
  compile: 'Compile', check: 'Check', analyze: 'Analyze', format: 'Format', run: 'Run', save: 'Save', download: 'Download', copy: 'Copy', close: 'Close',
  search: 'Search…', filter: 'Filter', all: 'All', none: 'None', yes: 'Yes', no: 'No', name: 'Name', kind: 'Kind', zone: 'Zone', node: 'Node',
  data: 'Data', action: 'Action', effect: 'Effect', priority: 'Priority', severity: 'Severity', status: 'Status', path: 'Path', evidence: 'Evidence',
  fix: 'Suggested fix', confidence: 'Confidence', category: 'Category', rule: 'Rule', policy: 'Policy', flow: 'Flow', from: 'From', to: 'To',
  controls: 'Controls', missing: 'Missing', details: 'Details', example: 'Example', examples: 'Examples', source: 'Source', language: 'Language',
  theme: 'Theme', appearance: 'Appearance', system: 'Windows default', light: 'Light', dark: 'Dark', amoled: 'AMOLED', red: 'Red', blue: 'Blue',
  ready: 'Ready', analyzing: 'Analyzing…', compiling: 'Compiling…', errors: 'Errors', warnings: 'Warnings', notices: 'Notices', findings: 'Findings',
  optimizations: 'Optimizations', passed: 'Passed', failed: 'Failed', total: 'Total', loading: 'Loading…', noData: 'Nothing to show yet — load an example or compile a model.',
  backendDown: 'The THREADZERO server is not reachable. Start it with: threadzero serve', commandPalette: 'Command palette', shortcuts: 'Keyboard shortcuts',
  line: 'Line', decision: 'Decision', reason: 'Reason', obligations: 'Obligations', request: 'Request', result: 'Result', version: 'Version', size: 'Size',
  // studio
  'studio.title': 'Architecture Studio', 'studio.subtitle': 'Security as compilable architecture', 'studio.loadExample': 'Load an example', 'studio.nodes': 'Nodes',
  'studio.flows': 'Flows', 'studio.zones': 'Zones', 'studio.crossings': 'Boundary crossings', 'studio.rules': 'Policy rules', 'studio.properties': 'Security properties',
  'studio.holds': 'holds', 'studio.violated': 'violated', 'studio.disabled': 'disabled', 'studio.bySeverity': 'Findings by severity', 'studio.assertions': 'Assertions',
  'studio.coverage': 'Policy coverage', 'studio.open': 'Open in editor',
  // editor
  'editor.title': 'DSL Editor', 'editor.diagnostics': 'Live diagnostics', 'editor.playground': 'Compiler Playground', 'editor.ast': 'AST', 'editor.graph': 'Semantic graph',
  'editor.policy': 'Policy output', 'editor.wasm': 'WASM artifact', 'editor.tests': 'Test results', 'editor.noErrors': 'No errors — the model compiles.',
  'editor.wat': 'WAT', 'editor.rego': 'Rego', 'editor.json': 'JSON artifact', 'editor.preview': 'Compile preview', 'editor.reset': 'Reset', 'editor.docs': 'DSL reference',
  // canvas
  'canvas.title': 'Trust Boundary Canvas', 'canvas.view2d': '2D graph', 'canvas.view3d': '3D security graph', 'canvas.palette': 'Palette (drag onto a zone)',
  'canvas.inspector': 'Inspector', 'canvas.hint': 'Drag a palette item onto a zone to declare it in the DSL; drag from a node handle to another node to draw a data flow.',
  'canvas.newFlow': 'New flow', 'canvas.dataType': 'Data type', 'canvas.operation': 'Operation', 'canvas.create': 'Create', 'canvas.crossing': 'boundary crossing',
  'canvas.internal': 'inside zone', 'canvas.legend': 'Legend',
  // flows
  'flows.title': 'Data Flow Explorer', 'flows.pick': 'Choose a data type', 'flows.origins': 'Origins', 'flows.stores': 'Stores', 'flows.journeys': 'Journeys (origin → sink)',
  'flows.timeline': 'Timeline', 'flows.lineage': 'Lineage', 'flows.declass': 'Declassification', 'flows.propagation': 'Classification propagation', 'flows.effective': 'Effective class',
  // policies
  'policies.title': 'Policy Studio', 'policies.rules': 'Rules (precedence order)', 'policies.conflicts': 'Conflicts', 'policies.coverage': 'Coverage', 'policies.optimize': 'Optimization proposals',
  'policies.inspector': 'Policy Inspector', 'policies.permissions': 'Permission Explorer', 'policies.role': 'Role', 'policies.mfa': 'MFA', 'policies.explore': 'Explore',
  'policies.covered': 'covered', 'policies.uncovered': 'no enforcement', 'policies.condition': 'Condition', 'policies.windows': 'Time windows',
  // console
  'console.title': 'Compiler Console', 'console.pipeline': 'Security build pipeline', 'console.log': 'Log', 'console.signed': 'signed', 'console.lock': 'Lockfile',
  'console.artifact': 'Artifact', 'console.build': 'Build', 'console.step.parse': 'Parse', 'console.step.validate': 'Validate', 'console.step.analyze': 'Analyze',
  'console.step.refactor': 'Refactor proposals', 'console.step.generate': 'Generate', 'console.step.test': 'Test', 'console.step.package': 'Package', 'console.step.sign': 'Sign', 'console.step.publish': 'Publish (approval)',
  // findings
  'findings.title': 'Security Findings', 'findings.none': 'No findings — the graph analyzer did not detect exposure paths.', 'findings.refactor': 'Refactor…', 'findings.explain': 'Explain',
  'findings.rule': 'Violated rule', 'findings.affected': 'Affected nodes',
  // refactor
  'refactor.title': 'Refactoring Lab', 'refactor.current': 'Current architecture', 'refactor.candidate': 'Candidate', 'refactor.pre': 'Preconditions', 'refactor.post': 'Postconditions',
  'refactor.transform': 'Transformation', 'refactor.impact': 'Security impact', 'refactor.functional': 'Functional impact', 'refactor.cost': 'Cost estimate', 'refactor.residual': 'Residual risk',
  'refactor.diff': 'Diff (DSL)', 'refactor.scorecard': 'Scorecard (no single score)', 'refactor.pick': 'Choose a finding', 'refactor.noCandidates': 'No automatic candidate for this finding.',
  'refactor.removed': 'findings removed', 'refactor.added': 'findings added', 'refactor.remaining': 'remaining', 'refactor.notice': 'Candidates are proposals. Nothing is applied to production.',
  'refactor.apply': 'Load candidate into editor', 'refactor.equivalent': 'functionally equivalent', 'refactor.components': 'components added',
  // simulator
  'sim.title': 'Policy Simulator', 'sim.subject': 'Subject', 'sim.roles': 'Roles', 'sim.deviceTrust': 'Device trust', 'sim.resource': 'Resource', 'sim.env': 'Environment', 'sim.time': 'Time',
  'sim.day': 'Day', 'sim.hour': 'Hour', 'sim.approved': 'Approved', 'sim.emergency': 'Emergency', 'sim.secure': 'Secure channel', 'sim.tenant': 'Tenant match', 'sim.evaluate': 'Evaluate in WASM',
  'sim.steps': 'Reasoning', 'sim.matched': 'Matched rules', 'sim.boundary': 'Boundary Simulation Studio', 'sim.srcZone': 'Source zone', 'sim.dstZone': 'Destination zone',
  'sim.provided': 'Provided controls', 'sim.simulateFlow': 'Simulate crossing', 'sim.context': 'Context flags', 'sim.graph': 'Authorization reasoning graph', 'sim.allRules': 'All rules',
  // wasm
  'wasm.title': 'WASM Runtime Lab', 'wasm.exports': 'Exports', 'wasm.size': 'Module size', 'wasm.hash': 'SHA-256', 'wasm.inBrowser': 'Run in the browser sandbox', 'wasm.perf': 'Performance / Scale Lab',
  'wasm.rules': 'Rule counts', 'wasm.requests': 'Requests', 'wasm.threads': 'Threads', 'wasm.faults': 'Fault injection', 'wasm.runFaults': 'Run fault scenarios', 'wasm.safe': 'safe failure', 'wasm.unsafe': 'UNSAFE',
  'wasm.host': 'Runtime host (canary / rollback)', 'wasm.load': 'Load', 'wasm.activate': 'Activate', 'wasm.canary': 'Canary', 'wasm.rollback': 'Rollback', 'wasm.throughput': 'Throughput',
  // tests
  'tests.title': 'Test Lab', 'tests.run': 'Run all tests', 'tests.trace': 'Trace', 'tests.expected': 'Expected', 'tests.actual': 'Actual', 'tests.onlyFailed': 'Only failures', 'tests.targets': 'Compare JS + Rego targets',
  // deps
  'deps.title': 'Dependency Graph', 'deps.entity': 'Entity', 'deps.impacted': 'Impacted entities', 'deps.direction': 'Direction', 'deps.dependents': 'Who depends on it', 'deps.dependencies': 'What it depends on',
  // impact
  'impact.title': 'Change Impact', 'impact.base': 'Base', 'impact.head': 'Head (current editor)', 'impact.run': 'Analyze impact', 'impact.new': 'New findings', 'impact.fixed': 'Fixed', 'impact.remaining': 'Remaining',
  'impact.regression': 'Security regression (policy replay)', 'impact.loosened': 'loosened', 'impact.tightened': 'tightened', 'impact.snapshots': 'Security snapshots', 'impact.snapshot': 'Create snapshot', 'impact.history': 'Historical security graph',
  'impact.gate': 'Merge gate', 'impact.useExample': 'Use example as base',
  // registry
  'registry.title': 'Artifact Registry', 'registry.empty': 'No artifacts yet — compile a model.', 'registry.files': 'Files', 'registry.manifest': 'Manifest', 'registry.signature': 'Signature',
  'registry.load': 'Load into runtime host', 'registry.distribute': 'Distribute', 'registry.sourceHash': 'Source model hash', 'registry.compiler': 'Compiler',
  // ci
  'ci.title': 'CI Integration', 'ci.failOn': 'Fail the build on', 'ci.run': 'Run gate', 'ci.pass': 'Gate passed', 'ci.fail': 'Gate failed', 'ci.workflow': 'Workflow snippet', 'ci.sarif': 'SARIF', 'ci.junit': 'JUnit', 'ci.baseline': 'Baseline (optional)',
  // reports
  'reports.title': 'Reports', 'reports.kind': 'Report', 'reports.format': 'Format', 'reports.generate': 'Generate', 'reports.security': 'Architecture security document', 'reports.policies': 'Policy catalog',
  'reports.controls': 'Control matrix', 'reports.tests': 'Test matrix', 'reports.compliance': 'Compliance mapping (evidence only)', 'reports.dfd': 'Data flow diagram', 'reports.tbd': 'Trust boundary diagram', 'reports.all': 'Everything',
  // schedule
  'schedule.title': 'Access Windows', 'schedule.subtitle': 'Opening hours, maintenance and emergency windows', 'schedule.add': 'Add window', 'schedule.remove': 'Remove', 'schedule.days': 'Days', 'schedule.from': 'Opens', 'schedule.to': 'Closes',
  'schedule.tz': 'Time zone', 'schedule.kind': 'Type', 'schedule.open': 'Opening hours', 'schedule.maintenance': 'Maintenance', 'schedule.emergency': 'Emergency', 'schedule.now': 'Current time',
  'schedule.simulate': 'Simulate a different moment', 'schedule.openNow': 'Open now', 'schedule.closedNow': 'Closed now', 'schedule.closesIn': 'Closes in', 'schedule.opensIn': 'Opens in', 'schedule.nextOpen': 'Next opening',
  'schedule.nextClose': 'Next closing', 'schedule.lasts': 'Stays open for', 'schedule.insert': 'Insert into DSL', 'schedule.saved': 'Saved on the server', 'schedule.fromModel': 'Import from model', 'schedule.label': 'Label',
  'schedule.daily': 'Every day', 'schedule.weekdays': 'Weekdays', 'schedule.weekends': 'Weekends', 'schedule.never': 'never open', 'schedule.dslPreview': 'DSL preview',
  // assistant
  'assistant.title': 'AI Security Architecture Assistant', 'assistant.ask': 'Ask about the architecture…', 'assistant.send': 'Ask', 'assistant.tools': 'Tools used', 'assistant.proposalsOnly': 'The assistant only proposes. Every suggestion is verified by the compiler and linked to real nodes, flows and rules.',
  // admin
  'admin.title': 'Administration', 'admin.health': 'Server health', 'admin.keys': 'Signing keys', 'admin.newKey': 'Generate key', 'admin.log': 'Immutable decision log', 'admin.verifyLog': 'Verify chain', 'admin.host': 'Runtime host', 'admin.workspace': 'Workspace',
  // settings
  'settings.title': 'Settings', 'settings.direction': 'Layout direction', 'settings.rtl': 'Right-to-left (Persian)', 'settings.ltr': 'Left-to-right', 'settings.codeLtr': 'Code and diagrams always stay left-to-right.',
  // severity
  'sev.Critical': 'Critical', 'sev.High': 'High', 'sev.Medium': 'Medium', 'sev.Low': 'Low', 'sev.Info': 'Info',
  'sev.error': 'Error', 'sev.warning': 'Warning', 'sev.notice': 'Notice', 'sev.finding': 'Finding', 'sev.optimization': 'Optimization',
  days: 'Mon,Tue,Wed,Thu,Fri,Sat,Sun',
};

const fa: Partial<typeof en> = {
  appTagline: 'کامپایلر مرز اعتماد',
  'nav.studio': 'استودیوی معماری', 'nav.editor': 'ویرایشگر DSL', 'nav.canvas': 'بوم مرز اعتماد', 'nav.flows': 'کاوشگر جریان داده', 'nav.policies': 'استودیوی سیاست',
  'nav.console': 'کنسول کامپایلر', 'nav.findings': 'یافته‌های امنیتی', 'nav.refactor': 'آزمایشگاه بازسازی', 'nav.simulator': 'شبیه‌ساز سیاست', 'nav.wasm': 'آزمایشگاه WASM',
  'nav.tests': 'آزمایشگاه تست', 'nav.dependencies': 'گراف وابستگی', 'nav.impact': 'تحلیل اثر تغییر', 'nav.registry': 'مخزن آرتیفکت', 'nav.ci': 'یکپارچه‌سازی CI',
  'nav.reports': 'گزارش‌ها', 'nav.schedule': 'بازه‌های دسترسی', 'nav.assistant': 'دستیار هوشمند', 'nav.admin': 'مدیریت', 'nav.settings': 'تنظیمات',
  'nav.group.design': 'طراحی', 'nav.group.analyze': 'تحلیل', 'nav.group.runtime': 'زمان اجرا', 'nav.group.ship': 'انتشار', 'nav.group.manage': 'مدیریت',
  compile: 'کامپایل', check: 'بررسی', analyze: 'تحلیل', format: 'قالب‌بندی', run: 'اجرا', save: 'ذخیره', download: 'دانلود', copy: 'کپی', close: 'بستن', search: 'جستجو…', filter: 'فیلتر',
  all: 'همه', none: 'هیچ', yes: 'بله', no: 'خیر', name: 'نام', kind: 'نوع', zone: 'ناحیه', node: 'گره', data: 'داده', action: 'عمل', effect: 'اثر', priority: 'اولویت', severity: 'شدت',
  status: 'وضعیت', path: 'مسیر', evidence: 'شواهد', fix: 'راه‌حل پیشنهادی', confidence: 'اطمینان', category: 'دسته', rule: 'قانون', policy: 'سیاست', flow: 'جریان', from: 'از', to: 'به',
  controls: 'کنترل‌ها', missing: 'کم‌بود', details: 'جزئیات', example: 'نمونه', examples: 'نمونه‌ها', source: 'منبع', language: 'زبان', theme: 'پوسته', appearance: 'ظاهر',
  system: 'پیش‌فرض ویندوز', light: 'روشن', dark: 'تیره', amoled: 'آمولد', red: 'قرمز', blue: 'آبی', ready: 'آماده', analyzing: 'در حال تحلیل…', compiling: 'در حال کامپایل…',
  errors: 'خطاها', warnings: 'هشدارها', notices: 'یادداشت‌ها', findings: 'یافته‌ها', optimizations: 'بهینه‌سازی‌ها', passed: 'موفق', failed: 'ناموفق', total: 'کل', loading: 'در حال بارگذاری…',
  noData: 'هنوز چیزی برای نمایش نیست — یک نمونه بارگذاری یا مدل را کامپایل کنید.', backendDown: 'سرور THREADZERO در دسترس نیست. آن را اجرا کنید: threadzero serve',
  commandPalette: 'پالت دستورات', shortcuts: 'میان‌برهای صفحه‌کلید', line: 'خط', decision: 'تصمیم', reason: 'دلیل', obligations: 'تعهدات', request: 'درخواست', result: 'نتیجه', version: 'نسخه', size: 'اندازه',
  'studio.title': 'استودیوی معماری', 'studio.subtitle': 'امنیت به‌عنوان معماری قابل‌کامپایل', 'studio.loadExample': 'بارگذاری یک نمونه', 'studio.nodes': 'گره‌ها', 'studio.flows': 'جریان‌ها',
  'studio.zones': 'ناحیه‌ها', 'studio.crossings': 'عبور از مرز', 'studio.rules': 'قوانین سیاست', 'studio.properties': 'ویژگی‌های امنیتی', 'studio.holds': 'برقرار', 'studio.violated': 'نقض‌شده',
  'studio.disabled': 'غیرفعال', 'studio.bySeverity': 'یافته‌ها بر اساس شدت', 'studio.assertions': 'ادعاها', 'studio.coverage': 'پوشش سیاست', 'studio.open': 'باز کردن در ویرایشگر',
  'editor.title': 'ویرایشگر DSL', 'editor.diagnostics': 'عیب‌یابی زنده', 'editor.playground': 'زمین‌بازی کامپایلر', 'editor.ast': 'درخت نحو (AST)', 'editor.graph': 'گراف معنایی',
  'editor.policy': 'خروجی سیاست', 'editor.wasm': 'آرتیفکت WASM', 'editor.tests': 'نتایج تست', 'editor.noErrors': 'خطایی نیست — مدل کامپایل می‌شود.', 'editor.json': 'آرتیفکت JSON',
  'editor.preview': 'پیش‌نمایش کامپایل', 'editor.reset': 'بازنشانی',
  'canvas.title': 'بوم مرز اعتماد', 'canvas.view2d': 'گراف دوبعدی', 'canvas.view3d': 'گراف امنیتی سه‌بعدی', 'canvas.palette': 'پالت (روی یک ناحیه بکشید)', 'canvas.inspector': 'بازرس',
  'canvas.hint': 'یک مورد پالت را روی ناحیه رها کنید تا در DSL تعریف شود؛ از دستگیره یک گره به گره دیگر بکشید تا جریان داده رسم شود.', 'canvas.newFlow': 'جریان جدید', 'canvas.dataType': 'نوع داده',
  'canvas.operation': 'عملیات', 'canvas.create': 'ایجاد', 'canvas.crossing': 'عبور از مرز', 'canvas.internal': 'درون ناحیه', 'canvas.legend': 'راهنما',
  'flows.title': 'کاوشگر جریان داده', 'flows.pick': 'یک نوع داده انتخاب کنید', 'flows.origins': 'مبداها', 'flows.stores': 'محل ذخیره', 'flows.journeys': 'سفرها (مبدا ← مقصد)', 'flows.timeline': 'خط زمان',
  'flows.lineage': 'تبار داده', 'flows.declass': 'کاهش طبقه‌بندی', 'flows.propagation': 'انتشار طبقه‌بندی', 'flows.effective': 'طبقه مؤثر',
  'policies.title': 'استودیوی سیاست', 'policies.rules': 'قوانین (به ترتیب تقدم)', 'policies.conflicts': 'تعارض‌ها', 'policies.coverage': 'پوشش', 'policies.optimize': 'پیشنهادهای بهینه‌سازی',
  'policies.inspector': 'بازرس سیاست', 'policies.permissions': 'کاوشگر دسترسی', 'policies.role': 'نقش', 'policies.mfa': 'احراز چندعاملی', 'policies.explore': 'کاوش', 'policies.covered': 'پوشش‌داده‌شده',
  'policies.uncovered': 'بدون اعمال', 'policies.condition': 'شرط', 'policies.windows': 'بازه‌های زمانی',
  'console.title': 'کنسول کامپایلر', 'console.pipeline': 'خط لوله ساخت امنیتی', 'console.log': 'گزارش', 'console.signed': 'امضا شده', 'console.lock': 'فایل قفل', 'console.artifact': 'آرتیفکت',
  'console.build': 'ساخت', 'console.step.parse': 'تجزیه', 'console.step.validate': 'اعتبارسنجی', 'console.step.analyze': 'تحلیل', 'console.step.refactor': 'پیشنهاد بازسازی', 'console.step.generate': 'تولید',
  'console.step.test': 'تست', 'console.step.package': 'بسته‌بندی', 'console.step.sign': 'امضا', 'console.step.publish': 'انتشار (نیازمند تأیید)',
  'findings.title': 'یافته‌های امنیتی', 'findings.none': 'یافته‌ای نیست — تحلیلگر گراف مسیر آسیب‌پذیری پیدا نکرد.', 'findings.refactor': 'بازسازی…', 'findings.explain': 'توضیح', 'findings.rule': 'قانون نقض‌شده',
  'findings.affected': 'گره‌های متأثر',
  'refactor.title': 'آزمایشگاه بازسازی', 'refactor.current': 'معماری فعلی', 'refactor.candidate': 'نامزد', 'refactor.pre': 'پیش‌شرط‌ها', 'refactor.post': 'پس‌شرط‌ها', 'refactor.transform': 'تبدیل',
  'refactor.impact': 'اثر امنیتی', 'refactor.functional': 'اثر عملکردی', 'refactor.cost': 'برآورد هزینه', 'refactor.residual': 'ریسک باقی‌مانده', 'refactor.diff': 'تفاوت (DSL)',
  'refactor.scorecard': 'کارنامه (بدون امتیاز واحد)', 'refactor.pick': 'یک یافته انتخاب کنید', 'refactor.noCandidates': 'برای این یافته نامزد خودکاری وجود ندارد.', 'refactor.removed': 'یافتهٔ حذف‌شده',
  'refactor.added': 'یافتهٔ افزوده', 'refactor.remaining': 'باقی‌مانده', 'refactor.notice': 'نامزدها فقط پیشنهادند. چیزی روی محیط عملیاتی اعمال نمی‌شود.', 'refactor.apply': 'بارگذاری نامزد در ویرایشگر',
  'refactor.equivalent': 'معادل عملکردی', 'refactor.components': 'مؤلفهٔ افزوده',
  'sim.title': 'شبیه‌ساز سیاست', 'sim.subject': 'سوژه', 'sim.roles': 'نقش‌ها', 'sim.deviceTrust': 'اعتماد دستگاه', 'sim.resource': 'منبع', 'sim.env': 'محیط', 'sim.time': 'زمان', 'sim.day': 'روز', 'sim.hour': 'ساعت',
  'sim.approved': 'تأییدشده', 'sim.emergency': 'اضطراری', 'sim.secure': 'کانال امن', 'sim.tenant': 'تطابق مستأجر', 'sim.evaluate': 'ارزیابی در WASM', 'sim.steps': 'استدلال', 'sim.matched': 'قوانین منطبق',
  'sim.boundary': 'استودیوی شبیه‌سازی مرز', 'sim.srcZone': 'ناحیهٔ مبدا', 'sim.dstZone': 'ناحیهٔ مقصد', 'sim.provided': 'کنترل‌های موجود', 'sim.simulateFlow': 'شبیه‌سازی عبور', 'sim.context': 'پرچم‌های زمینه',
  'sim.graph': 'گراف استدلال مجوز', 'sim.allRules': 'همه قوانین',
  'wasm.title': 'آزمایشگاه زمان اجرای WASM', 'wasm.exports': 'صادرات', 'wasm.size': 'اندازه ماژول', 'wasm.hash': 'SHA-256', 'wasm.inBrowser': 'اجرا در سندباکس مرورگر', 'wasm.perf': 'آزمایشگاه کارایی و مقیاس',
  'wasm.rules': 'تعداد قوانین', 'wasm.requests': 'درخواست‌ها', 'wasm.threads': 'ریسمان‌ها', 'wasm.faults': 'تزریق خطا', 'wasm.runFaults': 'اجرای سناریوهای خطا', 'wasm.safe': 'شکست امن', 'wasm.unsafe': 'ناامن',
  'wasm.host': 'میزبان زمان اجرا (قناری / بازگشت)', 'wasm.load': 'بارگذاری', 'wasm.activate': 'فعال‌سازی', 'wasm.canary': 'قناری', 'wasm.rollback': 'بازگشت', 'wasm.throughput': 'توان عملیاتی',
  'tests.title': 'آزمایشگاه تست', 'tests.run': 'اجرای همهٔ تست‌ها', 'tests.trace': 'ردیابی', 'tests.expected': 'مورد انتظار', 'tests.actual': 'واقعی', 'tests.onlyFailed': 'فقط ناموفق‌ها', 'tests.targets': 'مقایسهٔ JS و Rego',
  'deps.title': 'گراف وابستگی', 'deps.entity': 'موجودیت', 'deps.impacted': 'موجودیت‌های متأثر', 'deps.direction': 'جهت', 'deps.dependents': 'چه چیزی به آن وابسته است', 'deps.dependencies': 'به چه چیزی وابسته است',
  'impact.title': 'تحلیل اثر تغییر', 'impact.base': 'پایه', 'impact.head': 'مقصد (ویرایشگر فعلی)', 'impact.run': 'تحلیل اثر', 'impact.new': 'یافته‌های جدید', 'impact.fixed': 'رفع‌شده', 'impact.remaining': 'باقی‌مانده',
  'impact.regression': 'رگرسیون امنیتی (بازپخش سیاست)', 'impact.loosened': 'سهل‌گیرانه‌تر', 'impact.tightened': 'سخت‌گیرانه‌تر', 'impact.snapshots': 'تصاویر لحظه‌ای امنیتی', 'impact.snapshot': 'ایجاد تصویر لحظه‌ای',
  'impact.history': 'گراف تاریخی امنیت', 'impact.gate': 'دروازهٔ ادغام', 'impact.useExample': 'استفاده از نمونه به‌عنوان پایه',
  'registry.title': 'مخزن آرتیفکت', 'registry.empty': 'هنوز آرتیفکتی نیست — یک مدل را کامپایل کنید.', 'registry.files': 'فایل‌ها', 'registry.manifest': 'مانیفست', 'registry.signature': 'امضا',
  'registry.load': 'بارگذاری در میزبان اجرا', 'registry.distribute': 'توزیع', 'registry.sourceHash': 'هش مدل منبع', 'registry.compiler': 'کامپایلر',
  'ci.title': 'یکپارچه‌سازی CI', 'ci.failOn': 'شکست ساخت در', 'ci.run': 'اجرای دروازه', 'ci.pass': 'دروازه عبور کرد', 'ci.fail': 'دروازه شکست خورد', 'ci.workflow': 'قطعهٔ گردش‌کار', 'ci.baseline': 'مبنا (اختیاری)',
  'reports.title': 'گزارش‌ها', 'reports.kind': 'گزارش', 'reports.format': 'قالب', 'reports.generate': 'تولید', 'reports.security': 'سند امنیتی معماری', 'reports.policies': 'فهرست سیاست‌ها', 'reports.controls': 'ماتریس کنترل',
  'reports.tests': 'ماتریس تست', 'reports.compliance': 'نگاشت انطباق (فقط شواهد)', 'reports.dfd': 'نمودار جریان داده', 'reports.tbd': 'نمودار مرز اعتماد', 'reports.all': 'همه چیز',
  'schedule.title': 'بازه‌های دسترسی', 'schedule.subtitle': 'ساعات کاری، نگهداری و بازه‌های اضطراری', 'schedule.add': 'افزودن بازه', 'schedule.remove': 'حذف', 'schedule.days': 'روزها', 'schedule.from': 'شروع', 'schedule.to': 'پایان',
  'schedule.tz': 'منطقهٔ زمانی', 'schedule.kind': 'نوع', 'schedule.open': 'ساعات کاری', 'schedule.maintenance': 'نگهداری', 'schedule.emergency': 'اضطراری', 'schedule.now': 'زمان فعلی', 'schedule.simulate': 'شبیه‌سازی زمان دیگر',
  'schedule.openNow': 'اکنون باز است', 'schedule.closedNow': 'اکنون بسته است', 'schedule.closesIn': 'بسته می‌شود تا', 'schedule.opensIn': 'باز می‌شود تا', 'schedule.nextOpen': 'بازشدن بعدی', 'schedule.nextClose': 'بسته‌شدن بعدی',
  'schedule.lasts': 'مدت باز بودن', 'schedule.insert': 'درج در DSL', 'schedule.saved': 'روی سرور ذخیره شد', 'schedule.fromModel': 'واردکردن از مدل', 'schedule.label': 'برچسب', 'schedule.daily': 'هر روز', 'schedule.weekdays': 'روزهای کاری',
  'schedule.weekends': 'آخر هفته', 'schedule.never': 'هرگز باز نیست', 'schedule.dslPreview': 'پیش‌نمایش DSL',
  'assistant.title': 'دستیار هوشمند معماری امنیت', 'assistant.ask': 'دربارهٔ معماری بپرسید…', 'assistant.send': 'بپرس', 'assistant.tools': 'ابزارهای استفاده‌شده',
  'assistant.proposalsOnly': 'دستیار فقط پیشنهاد می‌دهد. هر پیشنهاد توسط کامپایلر تأیید شده و به گره‌ها، جریان‌ها و قوانین واقعی متصل است.',
  'admin.title': 'مدیریت', 'admin.health': 'سلامت سرور', 'admin.keys': 'کلیدهای امضا', 'admin.newKey': 'ایجاد کلید', 'admin.log': 'گزارش تصمیم تغییرناپذیر', 'admin.verifyLog': 'راستی‌آزمایی زنجیره', 'admin.host': 'میزبان زمان اجرا', 'admin.workspace': 'فضای کار',
  'settings.title': 'تنظیمات', 'settings.direction': 'جهت چیدمان', 'settings.rtl': 'راست‌به‌چپ (فارسی)', 'settings.ltr': 'چپ‌به‌راست', 'settings.codeLtr': 'کد و نمودارها همیشه چپ‌به‌راست می‌مانند.',
  'sev.Critical': 'بحرانی', 'sev.High': 'زیاد', 'sev.Medium': 'متوسط', 'sev.Low': 'کم', 'sev.Info': 'اطلاعاتی', 'sev.error': 'خطا', 'sev.warning': 'هشدار', 'sev.notice': 'یادداشت', 'sev.finding': 'یافته', 'sev.optimization': 'بهینه‌سازی',
  days: 'دوشنبه,سه‌شنبه,چهارشنبه,پنجشنبه,جمعه,شنبه,یکشنبه',
};

const zh: Partial<typeof en> = {
  appTagline: '信任边界编译器',
  'nav.studio': '架构工作室', 'nav.editor': 'DSL 编辑器', 'nav.canvas': '信任边界画布', 'nav.flows': '数据流浏览器', 'nav.policies': '策略工作室', 'nav.console': '编译器控制台',
  'nav.findings': '安全发现', 'nav.refactor': '重构实验室', 'nav.simulator': '策略模拟器', 'nav.wasm': 'WASM 运行时实验室', 'nav.tests': '测试实验室', 'nav.dependencies': '依赖图',
  'nav.impact': '变更影响', 'nav.registry': '制品注册表', 'nav.ci': 'CI 集成', 'nav.reports': '报告', 'nav.schedule': '访问时段', 'nav.assistant': 'AI 助手', 'nav.admin': '管理', 'nav.settings': '设置',
  'nav.group.design': '设计', 'nav.group.analyze': '分析', 'nav.group.runtime': '运行时', 'nav.group.ship': '发布', 'nav.group.manage': '管理',
  compile: '编译', check: '检查', analyze: '分析', format: '格式化', run: '运行', save: '保存', download: '下载', copy: '复制', close: '关闭', search: '搜索…', filter: '筛选', all: '全部', none: '无', yes: '是', no: '否',
  name: '名称', kind: '类型', zone: '区域', node: '节点', data: '数据', action: '操作', effect: '效果', priority: '优先级', severity: '严重程度', status: '状态', path: '路径', evidence: '证据', fix: '建议修复',
  confidence: '置信度', category: '类别', rule: '规则', policy: '策略', flow: '数据流', from: '来源', to: '目标', controls: '控制措施', missing: '缺失', details: '详情', example: '示例', examples: '示例', source: '源码',
  language: '语言', theme: '主题', appearance: '外观', system: 'Windows 默认', light: '浅色', dark: '深色', amoled: 'AMOLED', red: '红色', blue: '蓝色', ready: '就绪', analyzing: '分析中…', compiling: '编译中…',
  errors: '错误', warnings: '警告', notices: '提示', findings: '发现', optimizations: '优化建议', passed: '通过', failed: '失败', total: '总计', loading: '加载中…', noData: '暂无内容 — 请加载示例或编译模型。',
  backendDown: '无法连接 THREADZERO 服务器。请运行：threadzero serve', commandPalette: '命令面板', shortcuts: '键盘快捷键', line: '行', decision: '决策', reason: '原因', obligations: '义务', request: '请求',
  result: '结果', version: '版本', size: '大小',
  'studio.title': '架构工作室', 'studio.subtitle': '安全即可编译的架构', 'studio.loadExample': '加载示例', 'studio.nodes': '节点', 'studio.flows': '数据流', 'studio.zones': '区域', 'studio.crossings': '跨边界次数',
  'studio.rules': '策略规则', 'studio.properties': '安全属性', 'studio.holds': '成立', 'studio.violated': '被违反', 'studio.disabled': '已停用', 'studio.bySeverity': '按严重程度统计的发现', 'studio.assertions': '断言',
  'studio.coverage': '策略覆盖率', 'studio.open': '在编辑器中打开',
  'editor.title': 'DSL 编辑器', 'editor.diagnostics': '实时诊断', 'editor.playground': '编译器演练场', 'editor.ast': '抽象语法树', 'editor.graph': '语义图', 'editor.policy': '策略输出', 'editor.wasm': 'WASM 制品',
  'editor.tests': '测试结果', 'editor.noErrors': '没有错误 — 模型可以编译。', 'editor.json': 'JSON 制品', 'editor.preview': '编译预览', 'editor.reset': '重置',
  'canvas.title': '信任边界画布', 'canvas.view2d': '2D 图', 'canvas.view3d': '3D 安全图', 'canvas.palette': '组件面板（拖到区域上）', 'canvas.inspector': '检查器',
  'canvas.hint': '将组件拖到区域上即可在 DSL 中声明；从节点手柄拖到另一个节点即可绘制数据流。', 'canvas.newFlow': '新数据流', 'canvas.dataType': '数据类型', 'canvas.operation': '操作', 'canvas.create': '创建',
  'canvas.crossing': '跨边界', 'canvas.internal': '区域内部', 'canvas.legend': '图例',
  'flows.title': '数据流浏览器', 'flows.pick': '选择数据类型', 'flows.origins': '来源', 'flows.stores': '存储位置', 'flows.journeys': '旅程（来源 → 终点）', 'flows.timeline': '时间线', 'flows.lineage': '数据血缘',
  'flows.declass': '降级', 'flows.propagation': '分类传播', 'flows.effective': '有效级别',
  'policies.title': '策略工作室', 'policies.rules': '规则（按优先顺序）', 'policies.conflicts': '冲突', 'policies.coverage': '覆盖率', 'policies.optimize': '优化建议', 'policies.inspector': '策略检查器',
  'policies.permissions': '权限浏览器', 'policies.role': '角色', 'policies.mfa': '多因素认证', 'policies.explore': '浏览', 'policies.covered': '已覆盖', 'policies.uncovered': '未强制执行', 'policies.condition': '条件', 'policies.windows': '时间窗口',
  'console.title': '编译器控制台', 'console.pipeline': '安全构建流水线', 'console.log': '日志', 'console.signed': '已签名', 'console.lock': '锁文件', 'console.artifact': '制品', 'console.build': '构建',
  'console.step.parse': '解析', 'console.step.validate': '校验', 'console.step.analyze': '分析', 'console.step.refactor': '重构建议', 'console.step.generate': '生成', 'console.step.test': '测试', 'console.step.package': '打包',
  'console.step.sign': '签名', 'console.step.publish': '发布（需审批）',
  'findings.title': '安全发现', 'findings.none': '没有发现 — 图分析器未检测到暴露路径。', 'findings.refactor': '重构…', 'findings.explain': '解释', 'findings.rule': '被违反的规则', 'findings.affected': '受影响的节点',
  'refactor.title': '重构实验室', 'refactor.current': '当前架构', 'refactor.candidate': '候选方案', 'refactor.pre': '前置条件', 'refactor.post': '后置条件', 'refactor.transform': '变换', 'refactor.impact': '安全影响',
  'refactor.functional': '功能影响', 'refactor.cost': '成本估算', 'refactor.residual': '残余风险', 'refactor.diff': '差异 (DSL)', 'refactor.scorecard': '记分卡（不合并为单一分数）', 'refactor.pick': '选择一个发现',
  'refactor.noCandidates': '此发现没有自动候选方案。', 'refactor.removed': '项发现被消除', 'refactor.added': '项发现新增', 'refactor.remaining': '剩余', 'refactor.notice': '候选方案仅为建议，不会应用到生产环境。',
  'refactor.apply': '载入编辑器', 'refactor.equivalent': '功能等价', 'refactor.components': '新增组件',
  'sim.title': '策略模拟器', 'sim.subject': '主体', 'sim.roles': '角色', 'sim.deviceTrust': '设备信任', 'sim.resource': '资源', 'sim.env': '环境', 'sim.time': '时间', 'sim.day': '星期', 'sim.hour': '小时', 'sim.approved': '已批准',
  'sim.emergency': '紧急', 'sim.secure': '安全通道', 'sim.tenant': '租户匹配', 'sim.evaluate': '在 WASM 中评估', 'sim.steps': '推理过程', 'sim.matched': '匹配的规则', 'sim.boundary': '边界模拟工作室', 'sim.srcZone': '源区域',
  'sim.dstZone': '目标区域', 'sim.provided': '已提供的控制措施', 'sim.simulateFlow': '模拟跨越', 'sim.context': '上下文标志', 'sim.graph': '授权推理图', 'sim.allRules': '所有规则',
  'wasm.title': 'WASM 运行时实验室', 'wasm.exports': '导出函数', 'wasm.size': '模块大小', 'wasm.hash': 'SHA-256', 'wasm.inBrowser': '在浏览器沙箱中运行', 'wasm.perf': '性能与规模实验室', 'wasm.rules': '规则数量',
  'wasm.requests': '请求数', 'wasm.threads': '线程数', 'wasm.faults': '故障注入', 'wasm.runFaults': '运行故障场景', 'wasm.safe': '安全失败', 'wasm.unsafe': '不安全', 'wasm.host': '运行时宿主（金丝雀 / 回滚）',
  'wasm.load': '加载', 'wasm.activate': '激活', 'wasm.canary': '金丝雀', 'wasm.rollback': '回滚', 'wasm.throughput': '吞吐量',
  'tests.title': '测试实验室', 'tests.run': '运行全部测试', 'tests.trace': '追踪', 'tests.expected': '期望', 'tests.actual': '实际', 'tests.onlyFailed': '仅显示失败', 'tests.targets': '对比 JS 与 Rego',
  'deps.title': '依赖图', 'deps.entity': '实体', 'deps.impacted': '受影响的实体', 'deps.direction': '方向', 'deps.dependents': '谁依赖它', 'deps.dependencies': '它依赖什么',
  'impact.title': '变更影响', 'impact.base': '基线', 'impact.head': '当前（编辑器）', 'impact.run': '分析影响', 'impact.new': '新增发现', 'impact.fixed': '已修复', 'impact.remaining': '仍存在', 'impact.regression': '安全回归（策略重放）',
  'impact.loosened': '放宽', 'impact.tightened': '收紧', 'impact.snapshots': '安全快照', 'impact.snapshot': '创建快照', 'impact.history': '安全历史图', 'impact.gate': '合并门禁', 'impact.useExample': '以示例作为基线',
  'registry.title': '制品注册表', 'registry.empty': '还没有制品 — 请先编译模型。', 'registry.files': '文件', 'registry.manifest': '清单', 'registry.signature': '签名', 'registry.load': '载入运行时宿主', 'registry.distribute': '分发',
  'registry.sourceHash': '源模型哈希', 'registry.compiler': '编译器',
  'ci.title': 'CI 集成', 'ci.failOn': '在以下级别使构建失败', 'ci.run': '运行门禁', 'ci.pass': '门禁通过', 'ci.fail': '门禁失败', 'ci.workflow': '工作流片段', 'ci.baseline': '基线（可选）',
  'reports.title': '报告', 'reports.kind': '报告', 'reports.format': '格式', 'reports.generate': '生成', 'reports.security': '架构安全文档', 'reports.policies': '策略目录', 'reports.controls': '控制矩阵', 'reports.tests': '测试矩阵',
  'reports.compliance': '合规映射（仅作证据）', 'reports.dfd': '数据流图', 'reports.tbd': '信任边界图', 'reports.all': '全部',
  'schedule.title': '访问时段', 'schedule.subtitle': '营业时间、维护窗口与紧急窗口', 'schedule.add': '添加时段', 'schedule.remove': '删除', 'schedule.days': '星期', 'schedule.from': '开始', 'schedule.to': '结束', 'schedule.tz': '时区',
  'schedule.kind': '类型', 'schedule.open': '营业时间', 'schedule.maintenance': '维护', 'schedule.emergency': '紧急', 'schedule.now': '当前时间', 'schedule.simulate': '模拟其他时刻', 'schedule.openNow': '当前开放', 'schedule.closedNow': '当前关闭',
  'schedule.closesIn': '距离关闭', 'schedule.opensIn': '距离开放', 'schedule.nextOpen': '下次开放', 'schedule.nextClose': '下次关闭', 'schedule.lasts': '持续开放', 'schedule.insert': '插入 DSL', 'schedule.saved': '已保存到服务器',
  'schedule.fromModel': '从模型导入', 'schedule.label': '标签', 'schedule.daily': '每天', 'schedule.weekdays': '工作日', 'schedule.weekends': '周末', 'schedule.never': '从不开放', 'schedule.dslPreview': 'DSL 预览',
  'assistant.title': 'AI 安全架构助手', 'assistant.ask': '询问有关架构的问题…', 'assistant.send': '提问', 'assistant.tools': '使用的工具', 'assistant.proposalsOnly': '助手只提出建议。每条建议都经过编译器验证，并关联到真实的节点、数据流和规则。',
  'admin.title': '管理', 'admin.health': '服务器状态', 'admin.keys': '签名密钥', 'admin.newKey': '生成密钥', 'admin.log': '不可变决策日志', 'admin.verifyLog': '校验哈希链', 'admin.host': '运行时宿主', 'admin.workspace': '工作区',
  'settings.title': '设置', 'settings.direction': '布局方向', 'settings.rtl': '从右到左（波斯语）', 'settings.ltr': '从左到右', 'settings.codeLtr': '代码与图表始终保持从左到右。',
  'sev.Critical': '严重', 'sev.High': '高', 'sev.Medium': '中', 'sev.Low': '低', 'sev.Info': '信息', 'sev.error': '错误', 'sev.warning': '警告', 'sev.notice': '提示', 'sev.finding': '发现', 'sev.optimization': '优化',
  days: '周一,周二,周三,周四,周五,周六,周日',
};

export type Key = keyof typeof en;
const dict: Record<Lang, Partial<Record<Key, string>>> = { en, fa, zh };

export function translate(lang: Lang, key: Key | string, vars?: Record<string, string | number>): string {
  let s = (dict[lang] as any)[key] ?? (en as any)[key] ?? String(key);
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, String(v));
  return s;
}

export const dirOf = (l: Lang) => LANGS.find((x) => x.id === l)!.dir;
export const dayNames = (l: Lang): string[] => translate(l, 'days').split(',');

/** Localized numbers (Persian digits for fa, plain for others). */
export function num(l: Lang, n: number | string): string {
  const s = String(n);
  if (l !== 'fa') return s;
  return s.replace(/[0-9]/g, (d) => '۰۱۲۳۴۵۶۷۸۹'[+d]);
}
