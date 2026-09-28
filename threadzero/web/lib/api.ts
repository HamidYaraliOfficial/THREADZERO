export const API = process.env.NEXT_PUBLIC_API ?? '';

export async function api<T = any>(path: string, body?: any, method?: string): Promise<T> {
  const res = await fetch(API + path, {
    method: method ?? (body === undefined ? 'GET' : 'POST'),
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { const j = await res.json(); detail = j.detail ?? JSON.stringify(j); } catch { /* ignore */ }
    throw new Error(`${res.status}: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
  }
  const ct = res.headers.get('content-type') ?? '';
  return (ct.includes('json') ? res.json() : res.text()) as any;
}
export const apiBytes = async (path: string) => new Uint8Array(await (await fetch(API + path)).arrayBuffer());
