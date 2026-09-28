import { StreamLanguage } from '@codemirror/language';

const KEYWORDS = new Set(['project', 'import', 'classification', 'zone', 'role', 'env', 'action', 'location', 'data', 'assign', 'window', 'flow', 'boundary', 'policy', 'rule', 'assert', 'constraint',
  'declassify', 'separation', 'delegate', 'property', 'workflow', 'template', 'apply', 'user', 'identity', 'device', 'application', 'service', 'api', 'database', 'queue', 'filestore', 'cloud', 'secret', 'external', 'agent', 'approval']);
const WORDS = new Set(['in', 'from', 'to', 'carries', 'op', 'when', 'reason', 'obligations', 'and', 'or', 'not', 'trust', 'kind', 'class', 'rank', 'scope', 'extends', 'version', 'timezone', 'priority', 'max_class', 'never', 'enters', 'must', 'must_not', 'must_have', 'request']);
const EFFECTS = new Set(['allow', 'deny', 'require_mfa', 'require_approval', 'redact', 'encrypt', 'audit', 'rate_limit', 'tokenize', 'quarantine', 'require_trusted_zone']);

/** CodeMirror stream language for the THREADZERO DSL (code stays LTR even in the Persian UI). */
export const dslLanguage = StreamLanguage.define({
  token(stream) {
    if (stream.eatSpace()) return null;
    if (stream.match(/^(#|\/\/).*/)) return 'comment';
    if (stream.match(/^"(?:[^"\\]|\\.)*"/)) return 'string';
    if (stream.match(/^\d+(:\d\d|[smhdwy])?/)) return 'number';
    if (stream.match(/^(==|!=|>=|<=|->|=>|[<>])/)) return 'operator';
    if (stream.match(/^[A-Za-z_][A-Za-z0-9_.]*/)) {
      const w = stream.current();
      if (KEYWORDS.has(w)) return 'keyword';
      if (WORDS.has(w)) return 'atom';
      if (EFFECTS.has(w)) return 'variableName.special';
      if (/^[A-Z]/.test(w)) return 'typeName';
      return 'variableName';
    }
    stream.next();
    return null;
  },
  languageData: { commentTokens: { line: '#' } },
});
