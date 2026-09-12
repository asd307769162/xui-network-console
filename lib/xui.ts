export const XUI_NODES = [
  { alias: 'wf3', url: 'http://38.55.148.140:54321' },
  { alias: 'wf2', url: 'http://38.55.148.143:54321', collectorUrl: 'http://38.55.148.143:18787/v1/snapshot' },
  { alias: 'v2', url: 'http://103.15.91.249:54321', collectorUrl: 'http://103.15.91.249:18787/v1/snapshot' },
  { alias: 'j4', url: 'http://160.16.122.233:54321', collectorUrl: 'http://160.16.122.233:18787/v1/snapshot' },
  { alias: 't4', url: 'http://23.147.172.172:54321', collectorUrl: 'http://23.147.172.172:18787/v1/snapshot' },
  { alias: 't1', url: 'http://154.40.33.65:54321/1', collectorUrl: 'http://154.40.33.65:18787/v1/snapshot' },
] as const;

type JsonRecord = Record<string, unknown>;

function credentials() {
  const username = process.env.XUI_USERNAME;
  const password = process.env.XUI_PASSWORD;
  if (!username || !password) throw new Error('X-UI 凭据尚未配置');
  return { username, password };
}

function encodeForm(data: JsonRecord) {
  const form = new URLSearchParams();
  for (const [key, value] of Object.entries(data)) {
    form.set(key, typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value ?? ''));
  }
  return form;
}

async function post(root: string, path: string, data: JsonRecord, cookie?: string) {
  const response = await fetch(`${root}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'x-requested-with': 'XMLHttpRequest',
      referer: `${root}/xui/inbounds`,
      ...(cookie ? { cookie } : {}),
    },
    body: encodeForm(data),
    signal: AbortSignal.timeout(15_000),
  });
  const body = await response.json() as JsonRecord;
  if (!response.ok || !body.success) throw new Error(String(body.msg || `上游返回 ${response.status}`));
  return { body, cookie: response.headers.get('set-cookie')?.split(';')[0] };
}

async function session(root: string) {
  const { username, password } = credentials();
  const result = await post(root, '/login', { username, password });
  if (!result.cookie) throw new Error('登录成功但没有收到会话 Cookie');
  return result.cookie;
}

export async function listInbounds(alias: string) {
  const node = XUI_NODES.find((item) => item.alias === alias.toLowerCase());
  if (!node) throw new Error('未知服务器');
  const cookie = await session(node.url);
  const { body } = await post(node.url, '/xui/inbound/list', {}, cookie);
  return { node, inbounds: Array.isArray(body.obj) ? body.obj as JsonRecord[] : [] };
}

export async function setInboundEnabled(alias: string, id: number, enabled: boolean) {
  const { node, inbounds } = await listInbounds(alias);
  const inbound = inbounds.find((item) => Number(item.id) === id);
  if (!inbound) throw new Error('没有找到对应入站');
  const cookie = await session(node.url);
  const payload = { ...inbound, enable: enabled };
  const { body } = await post(node.url, `/xui/inbound/update/${id}`, payload, cookie);
  return { alias: node.alias, id, enabled, message: String(body.msg || '操作成功') };
}
