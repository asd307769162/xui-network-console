'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, AlertTriangle, ChevronDown, CircleGauge, Clock3, Eye, Filter, Globe2, History, MapPin, Network, Power, RefreshCw, Search, Server, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';

type ClientIp = { ip: string; location: string; connections?: number; firstSeen?: string; lastSeen?: string; online?: boolean; isNew?: boolean; scanner?: boolean; scannedPorts?: number };
type Port = { id: number; port: number; protocol: string; enabled: boolean; upload: number; download: number; ips: ClientIp[]; totalIps?: number; activeIpCount?: number; activeRegionCount?: number; activeNetworkCount?: number; recent1h?: number; recent24h?: number; overlapMinutes?: number; trusted?: boolean; observing?: boolean; note?: string };
type Node = { alias: string; ip: string; region: string; online: boolean; ports: Port[] };
type ModelContext = { registerTool: (tool: Record<string, unknown>, options?: { signal?: AbortSignal }) => void | Promise<void> };
type PortFlags = Record<string, { trusted?: boolean; observing?: boolean }>;

const PORT_FLAGS_STORAGE_KEY = 'xui-network-console.port-flags.v1';
const PORT_FLAGS_MIGRATED_KEY = 'xui-network-console.port-flags.server-migrated.v1';

const portFlagKey = (alias: string, id: number) => `${alias.toLowerCase()}:${id}`;

let notesRequest: Promise<Record<string, string>> | undefined;
function loadPortNotes() {
  notesRequest ??= fetch('/api/xui/notes').then(async (response) => {
    const data = await response.json() as { notes?: Record<string, string>; error?: string };
    if (!response.ok || !data.notes) throw new Error(data.error || '备注读取失败');
    return data.notes;
  }).catch((error) => { notesRequest = undefined; throw error; });
  return notesRequest;
}

function readLocalPortFlags(): PortFlags {
  try {
    const stored = window.localStorage.getItem(PORT_FLAGS_STORAGE_KEY);
    return stored ? JSON.parse(stored) as PortFlags : {};
  } catch {
    return {};
  }
}

function writeLocalPortFlags(flags: PortFlags) {
  try {
    window.localStorage.setItem(PORT_FLAGS_STORAGE_KEY, JSON.stringify(flags));
  } catch {
    // The UI state still updates when storage is unavailable.
  }
}

let portFlagsRequest: Promise<PortFlags> | undefined;
function loadPortFlags() {
  portFlagsRequest ??= fetch('/api/xui/flags').then(async (response) => {
    const data = await response.json() as { flags?: PortFlags; error?: string };
    if (!response.ok || !data.flags) throw new Error(data.error || '处理标记读取失败');
    const merged = { ...data.flags };
    const migrations: Promise<Response>[] = [];
    let shouldMigrate = false;
    try { shouldMigrate = window.localStorage.getItem(PORT_FLAGS_MIGRATED_KEY) !== '1'; } catch { /* Server data remains authoritative. */ }
    if (shouldMigrate) {
      for (const [key, entry] of Object.entries(readLocalPortFlags())) {
        const server = merged[key] || {};
        const next = { trusted: Boolean(server.trusted || entry.trusted), observing: Boolean(server.observing || entry.observing) };
        merged[key] = next;
        if (next.trusted !== Boolean(server.trusted) || next.observing !== Boolean(server.observing)) {
          const split = key.lastIndexOf(':');
          migrations.push(fetch('/api/xui/flags', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ alias: key.slice(0, split), id: Number(key.slice(split + 1)), ...next }) }));
        }
      }
    }
    if (migrations.length) {
      const responses = await Promise.all(migrations);
      if (responses.some((item) => !item.ok)) throw new Error('本机已有标记迁移失败');
    }
    if (shouldMigrate) try { window.localStorage.setItem(PORT_FLAGS_MIGRATED_KEY, '1'); } catch { /* Ignore unavailable browser storage. */ }
    writeLocalPortFlags(merged);
    return merged;
  }).catch((error) => { portFlagsRequest = undefined; throw error; });
  return portFlagsRequest;
}

function applyPortFlags(nodes: Node[], flags: PortFlags) {
  return nodes.map((node) => ({
    ...node,
    ports: node.ports.map((port) => ({ ...port, ...flags[portFlagKey(node.alias, port.id)] })),
  }));
}

const initialNodes: Node[] = [
  { alias: 'T4', ip: '23.147.172.172', region: '美国 · 洛杉矶', online: true, ports: [
    { id: 1, port: 55555, protocol: 'dokodemo-door', enabled: true, upload: 387.4, download: 921.7, ips: [
      { ip: '112.18.127.22', location: '中国 · 浙江 · 移动 · AS9808', firstSeen: '18:31', lastSeen: '现在', online: true },
      { ip: '118.117.103.96', location: '中国 · 四川 · 电信 · AS4134', firstSeen: '18:42', lastSeen: '现在', online: true, isNew: true },
    ], recent1h: 2, recent24h: 4, overlapMinutes: 26 },
    { id: 2, port: 41018, protocol: 'dokodemo-door', enabled: true, upload: 48.2, download: 173.9, ips: [{ ip: '39.144.193.158', location: '中国 · 北京 · 移动 · AS9808', firstSeen: '17:54', lastSeen: '现在', online: true }], recent1h: 1, recent24h: 2 },
    { id: 3, port: 41615, protocol: 'dokodemo-door', enabled: false, upload: 0.4, download: 1.8, ips: [] },
  ] },
  { alias: 'WF3', ip: '38.55.148.140', region: '中国香港', online: true, ports: [
    { id: 8, port: 21721, protocol: 'dokodemo-door', enabled: true, upload: 129.3, download: 486.1, ips: [
      { ip: '223.104.41.77', location: '中国 · 广东 · 移动 · AS9808', firstSeen: '18:16', lastSeen: '现在', online: true },
      { ip: '2409:8a1e::18', location: '中国 · 广东 · 移动 · AS9808', firstSeen: '18:17', lastSeen: '现在', online: true },
    ], recent1h: 2, recent24h: 2, overlapMinutes: 35, trusted: true },
    { id: 9, port: 30977, protocol: 'dokodemo-door', enabled: true, upload: 2.1, download: 4.8, ips: [] },
  ] },
  { alias: 'W0', ip: '154.40.33.44', region: '美国 · 圣何塞', online: false, ports: [
    { id: 16, port: 53009, protocol: 'dokodemo-door', enabled: true, upload: 76.6, download: 244.2, ips: [] },
  ] },
];

const formatTraffic = (gb: number) => gb >= 1024 ? `${(gb / 1024).toFixed(2)} TB` : `${gb.toFixed(1)} GB`;
const formatSeenAt = (value?: string) => {
  if (!value || value === '待采集' || value === '现在') return value || '待采集';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false,
  }).format(date).replace('/', '-');
};
type FilterState = 'all' | 'enabled' | 'disabled' | 'concurrent' | 'crossRegion' | 'newIp' | 'trusted';

function riskFor(port: Port) {
  const active = port.ips.filter((item) => item.online !== false && !item.scanner);
  const regions = new Set(active.map((item) => item.location.split('·').slice(0, 3).join('·')));
  const networks = new Set(active.map((item) => item.location.split('·').slice(-2).join('·')));
  const activeCount = port.activeIpCount ?? active.length;
  const crossRegion = (port.activeRegionCount ?? regions.size) > 1;
  const crossNetwork = (port.activeNetworkCount ?? networks.size) > 1;
  if (port.trusted) return { level: 0, label: '已信任', reason: '已人工确认', tone: 'text-sky-300 bg-sky-400/10 border-sky-400/15', crossRegion };
  if (activeCount >= 3) return { level: 3, label: '高风险', reason: `${activeCount} 个 IP 同时活跃`, tone: 'text-rose-300 bg-rose-400/10 border-rose-400/20', crossRegion };
  if (activeCount >= 2 && (crossRegion || crossNetwork)) return { level: 3, label: '高风险', reason: `跨地区/运营商重叠 ${port.overlapMinutes || 0} 分钟`, tone: 'text-rose-300 bg-rose-400/10 border-rose-400/20', crossRegion };
  if (activeCount >= 2) return { level: 2, label: '疑似共享', reason: `同时活跃 ${port.overlapMinutes || 0} 分钟`, tone: 'text-amber-300 bg-amber-400/10 border-amber-400/20', crossRegion };
  if ((port.recent24h || activeCount) >= 3) return { level: 1, label: '观察', reason: '24 小时出现多个 IP', tone: 'text-violet-300 bg-violet-400/10 border-violet-400/20', crossRegion };
  return { level: 0, label: '正常', reason: activeCount ? '未发现并发' : '暂无活跃 IP', tone: 'text-emerald-300 bg-emerald-400/10 border-emerald-400/15', crossRegion };
}

export default function Home() {
  const [nodes, setNodes] = useState(initialNodes);
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<FilterState>('all');
  const [pending, setPending] = useState<{ alias: string; id: number; next: boolean } | null>(null);
  const [source, setSource] = useState<'demo' | 'live'>('demo');
  const [message, setMessage] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;

  const stats = useMemo(() => {
    const ports = nodes.flatMap((node) => node.ports);
    return { servers: nodes.filter((node) => node.online).length, ports: ports.length, enabled: ports.filter((port) => port.enabled).length, risky: ports.filter((port) => riskFor(port).level >= 2).length, traffic: ports.reduce((sum, port) => sum + port.upload + port.download, 0) };
  }, [nodes]);

  const visibleNodes = useMemo(() => nodes.map((node) => ({ ...node, ports: node.ports.filter((port) => {
    const haystack = `${node.alias} ${node.ip} ${port.port} ${port.protocol} ${port.ips.map((item) => `${item.ip} ${item.location}`).join(' ')}`.toLowerCase();
    const matches = haystack.includes(query.toLowerCase());
    const risk = riskFor(port);
    const activeCount = port.activeIpCount ?? port.ips.filter((item) => item.online !== false && !item.scanner).length;
    const stateMatches = status === 'all' || (status === 'enabled' && port.enabled) || (status === 'disabled' && !port.enabled) || (status === 'concurrent' && !port.trusted && activeCount >= 2) || (status === 'crossRegion' && !port.trusted && risk.crossRegion) || (status === 'newIp' && port.ips.some((item) => item.isNew && !item.scanner)) || (status === 'trusted' && port.trusted);
    return matches && stateMatches;
  }).sort((a, b) => riskFor(b).level - riskFor(a).level) })).filter((node) => node.ports.length > 0).sort((a, b) => Math.max(...b.ports.map((port) => riskFor(port).level)) - Math.max(...a.ports.map((port) => riskFor(port).level))), [nodes, query, status]);

  const setPortFlag = async (alias: string, id: number, flag: 'trusted' | 'observing') => {
    const currentPort = nodesRef.current.find((node) => node.alias === alias)?.ports.find((port) => port.id === id);
    if (!currentPort) return;
    const entry = { trusted: Boolean(currentPort.trusted), observing: Boolean(currentPort.observing), [flag]: !currentPort[flag] };
    setMessage('正在保存处理标记…');
    try {
      const response = await fetch('/api/xui/flags', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ alias, id, ...entry }) });
      const data = await response.json() as { error?: string };
      if (!response.ok) throw new Error(data.error || '处理标记保存失败');
      setNodes((current) => current.map((node) => node.alias === alias ? { ...node, ports: node.ports.map((port) => port.id === id ? { ...port, ...entry } : port) } : node));
      const flags = await loadPortFlags();
      const key = portFlagKey(alias, id);
      if (!entry.trusted && !entry.observing) delete flags[key]; else flags[key] = entry;
      writeLocalPortFlags(flags);
      setMessage(flag === 'trusted' ? '可信标记已保存到服务器。' : '观察状态已保存到服务器；自动关闭端口保持关闭。');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '处理标记保存失败');
    }
  };

  const refreshLive = async () => {
    setRefreshing(true);
    setMessage('');
    try {
      const response = await fetch('/api/xui/snapshot');
      const data = await response.json() as { nodes?: Node[]; error?: string };
      if (!response.ok || !data.nodes) throw new Error(data.error || '实时读取失败');
      setNodes(applyPortFlags(data.nodes, await loadPortFlags()));
      setSource('live');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '实时读取失败');
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    void refreshLive();
  }, []);

  const confirmToggle = async () => {
    if (!pending) return;
    const change = pending;
    if (source === 'demo') {
      setNodes((current) => current.map((node) => node.alias === change.alias ? { ...node, ports: node.ports.map((port) => port.id === change.id ? { ...port, enabled: change.next } : port) } : node));
      setPending(null);
      setMessage('演示状态已更新；配置凭据后会提交到真实 x-ui 面板。');
      return;
    }
    try {
      const response = await fetch('/api/xui/toggle', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ alias: change.alias, id: change.id, enabled: change.next }) });
      const data = await response.json() as { error?: string };
      if (!response.ok) throw new Error(data.error || '端口操作失败');
      setNodes((current) => current.map((node) => node.alias === change.alias ? { ...node, ports: node.ports.map((port) => port.id === change.id ? { ...port, enabled: change.next } : port) } : node));
      setMessage(`${change.alias} 端口状态已更新。`);
      setPending(null);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '端口操作失败');
    }
  };

  useEffect(() => {
    const context = (document as Document & { modelContext?: ModelContext }).modelContext;
    if (!context?.registerTool) return;
    const lifecycle = new AbortController();
    const register = async () => {
      await context.registerTool({
        name: 'filter_xui_ports', title: '筛选 X-UI 端口',
        description: '按关键字和状态筛选当前控制台中的服务器端口。',
        inputSchema: { type: 'object', properties: { query: { type: 'string' }, status: { type: 'string', enum: ['all', 'enabled', 'disabled', 'concurrent', 'crossRegion', 'newIp', 'trusted'] } }, required: ['query', 'status'], additionalProperties: false },
        annotations: { readOnlyHint: true, untrustedContentHint: false },
        execute(input: unknown) {
          const value = input as { query?: unknown; status?: unknown };
          if (typeof value.query !== 'string' || !['all','enabled','disabled','concurrent','crossRegion','newIp','trusted'].includes(String(value.status))) throw new Error('筛选参数无效');
          setQuery(value.query); setStatus(value.status as typeof status);
          return { query: value.query, status: value.status };
        },
      }, { signal: lifecycle.signal });
      await context.registerTool({
        name: 'stage_xui_port_toggle', title: '准备切换端口状态',
        description: '为指定服务器和端口打开二次确认框，不会直接修改服务器。',
        inputSchema: { type: 'object', properties: { alias: { type: 'string' }, port: { type: 'integer' }, enabled: { type: 'boolean' } }, required: ['alias', 'port', 'enabled'], additionalProperties: false },
        annotations: { readOnlyHint: false, untrustedContentHint: false },
        execute(input: unknown) {
          const value = input as { alias?: unknown; port?: unknown; enabled?: unknown };
          const node = nodesRef.current.find((item) => item.alias.toLowerCase() === String(value.alias).toLowerCase());
          const target = node?.ports.find((item) => item.port === Number(value.port));
          if (!node || !target || typeof value.enabled !== 'boolean') throw new Error('没有找到指定服务器或端口');
          setPending({ alias: node.alias, id: target.id, next: value.enabled });
          return { staged: true, alias: node.alias, port: target.port, enabled: value.enabled, requiresConfirmation: true };
        },
      }, { signal: lifecycle.signal });
    };
    void register().catch(() => undefined);
    return () => lifecycle.abort();
  }, []);

  return (
    <main className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-30 border-b border-white/8 bg-[#071019]/92 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1680px] items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <div className="flex min-w-0 items-center gap-3"><div className="grid size-10 shrink-0 place-items-center rounded-xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300"><Network className="size-5" /></div><div className="min-w-0"><h1 className="truncate text-base font-semibold tracking-tight sm:text-lg">X-UI 网络控制台</h1><p className="hidden text-xs text-slate-400 sm:block">端口、连接与流量实时视图</p></div></div>
          <div className="flex items-center gap-2 text-sm text-slate-400"><Badge className={source === 'live' ? 'bg-emerald-400/12 text-emerald-300' : 'bg-amber-400/12 text-amber-300'}>{source === 'live' ? '实时' : '演示'}</Badge><Button size="sm" variant="outline" onClick={refreshLive} disabled={refreshing} className="border-white/10 bg-white/5 hover:bg-white/10"><RefreshCw className={`size-4 ${refreshing ? 'animate-spin' : ''}`} />{refreshing ? '读取中' : '刷新'}</Button></div>
        </div>
      </header>

      <div className="mx-auto max-w-[1680px] px-4 py-5 sm:px-6 sm:py-7">
        {message && <div role="status" className="mb-4 rounded-xl border border-cyan-400/15 bg-cyan-400/7 px-4 py-3 text-sm text-cyan-100">{message}</div>}
        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {[
            ['在线服务器', `${stats.servers}/${nodes.length}`, Server, 'text-cyan-300'],
            ['监控端口', stats.ports, CircleGauge, 'text-violet-300'],
            ['启用端口', stats.enabled, Power, 'text-emerald-300'],
            ['疑似共享', stats.risky, AlertTriangle, 'text-amber-300'],
            ['累计流量', formatTraffic(stats.traffic), Activity, 'text-sky-300'],
          ].map(([label, value, Icon, color]) => <article key={String(label)} className="metric-card"><div><p className="metric-label">{label as string}</p><p className="mt-2 text-2xl font-semibold tracking-tight">{value as string | number}</p></div><Icon className={`size-5 ${color}`} /></article>)}
        </section>

        <section className="mt-5 flex flex-col gap-3 rounded-2xl border border-white/8 bg-[#0b1622] p-3 lg:flex-row lg:items-center">
          <div className="relative min-w-0 flex-1"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-500" /><Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索服务器、端口、IP 或归属地" className="h-10 border-white/10 bg-[#071019] pl-9 placeholder:text-slate-600" /></div>
          <div className="flex items-center gap-1.5 overflow-x-auto"><Filter className="ml-1 size-4 shrink-0 text-slate-500" />{([['all','全部'],['concurrent','多人并发'],['crossRegion','跨地区'],['newIp','新 IP'],['trusted','已信任'],['enabled','已启用'],['disabled','已停用']] as const).map(([key,label]) => <Button key={key} size="sm" variant={status === key ? 'default' : 'ghost'} onClick={() => setStatus(key)} className={status === key ? 'bg-cyan-400 text-slate-950 hover:bg-cyan-300' : 'text-slate-400 hover:bg-white/5 hover:text-white'}>{label}</Button>)}</div>
        </section>

        <div className="sticky top-[65px] z-20 mt-4 hidden grid-cols-[90px_100px_120px_minmax(360px,1fr)_160px_210px] gap-3 rounded-xl border border-cyan-400/20 bg-[#101d29]/96 px-5 py-3.5 text-sm font-semibold tracking-wide text-slate-300 shadow-[0_12px_35px_rgba(0,0,0,.28)] backdrop-blur-xl lg:grid"><span>端口</span><span>状态</span><span>累计流量</span><span>来源 IP、归属与时间</span><span>共享判断</span><span className="text-right">处理</span></div>
        <div className="mt-3 space-y-3">
          {visibleNodes.map((node) => <NodePanel key={node.alias} node={node} setPending={setPending} setPortFlag={setPortFlag} setMessage={setMessage} />)}
          {!visibleNodes.length && <div className="rounded-2xl border border-dashed border-white/10 py-16 text-center text-slate-500">没有符合当前条件的端口</div>}
        </div>

        <footer className="mt-5 flex flex-col gap-2 border-t border-white/8 py-5 text-xs text-slate-600 sm:flex-row sm:items-center sm:justify-between"><span className="flex items-center gap-1.5"><ShieldCheck className="size-3.5" />所有开关操作均需二次确认；自动关闭端口：关闭</span><span>演示数据 · 接入采集代理后切换为实时状态</span></footer>
      </div>

      <AlertDialog open={Boolean(pending)} onOpenChange={(open) => !open && setPending(null)}><AlertDialogContent className="border-white/10 bg-[#101c28] text-slate-100"><AlertDialogHeader><AlertDialogTitle>确认{pending?.next ? '启用' : '停用'}端口？</AlertDialogTitle><AlertDialogDescription className="text-slate-400">该操作将修改 {pending?.alias} 的 x-ui 入站状态。提交前请确认不会中断正在使用的连接。</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter className="border-white/8 bg-white/[.025]"><AlertDialogCancel>取消</AlertDialogCancel><AlertDialogAction onClick={confirmToggle} className={pending?.next ? 'bg-emerald-500 text-white hover:bg-emerald-400' : 'bg-rose-500 text-white hover:bg-rose-400'}>确认{pending?.next ? '启用' : '停用'}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
    </main>
  );
}

function NodePanel({ node, setPending, setPortFlag, setMessage }: { node: Node; setPending: (value: { alias: string; id: number; next: boolean }) => void; setPortFlag: (alias: string, id: number, flag: 'trusted' | 'observing') => void; setMessage: (value: string) => void }) {
  const [open, setOpen] = useState(false);
  return <Collapsible open={open} onOpenChange={setOpen}><section className="overflow-hidden rounded-2xl border border-white/8 bg-[#0b1622] shadow-[0_18px_55px_rgba(0,0,0,.18)]">
    <CollapsibleTrigger className="group flex w-full items-center justify-between gap-4 px-4 py-4 text-left sm:px-5"><div className="flex min-w-0 items-center gap-3"><span className={`size-2.5 shrink-0 rounded-full ${node.online ? 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,.75)]' : 'bg-rose-400'}`} /><div className="min-w-0"><div className="flex items-center gap-2"><h2 className="font-semibold">{node.alias}</h2><Badge variant="outline" className="border-white/10 text-slate-400">{node.ports.length} 端口</Badge></div><p className="truncate text-sm text-slate-500">{node.ip} · {node.region}</p></div></div><ChevronDown className="size-5 text-slate-500 transition-transform group-data-panel-open:rotate-180" /></CollapsibleTrigger>
    {open && <CollapsibleContent><div className="border-t border-white/8">{node.ports.map((port) => <PortRow key={port.id} node={node} port={port} setPending={setPending} setPortFlag={setPortFlag} setMessage={setMessage} />)}</div></CollapsibleContent>}
  </section></Collapsible>;
}

function PortRow({ node, port, setPending, setPortFlag, setMessage }: { node: Node; port: Port; setPending: (value: { alias: string; id: number; next: boolean }) => void; setPortFlag: (alias: string, id: number, flag: 'trusted' | 'observing') => void; setMessage: (value: string) => void }) {
  const [showAllIps, setShowAllIps] = useState(false);
  const [visibleIpLimit, setVisibleIpLimit] = useState(100);
  const [allIps, setAllIps] = useState<ClientIp[] | null>(null);
  const [loadingIps, setLoadingIps] = useState(false);
  const [ipError, setIpError] = useState('');
  const [note, setNote] = useState('');
  const [savedNote, setSavedNote] = useState('');
  const [noteLoaded, setNoteLoaded] = useState(false);
  const [savingNote, setSavingNote] = useState(false);
  const [noteError, setNoteError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    loadPortNotes().then((notes) => {
      if (controller.signal.aborted) return;
      const value = notes[portFlagKey(node.alias, port.id)] || '';
      setNote(value); setSavedNote(value); setNoteLoaded(true);
    }).catch((error) => { if (!controller.signal.aborted) setNoteError(error instanceof Error ? error.message : '备注读取失败'); });
    return () => controller.abort();
  }, [node.alias, port.id]);
  const saveNote = async () => {
    setSavingNote(true); setNoteError('');
    try {
      const response = await fetch('/api/xui/notes', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ alias: node.alias, id: port.id, note }) });
      const data = await response.json() as { note?: string; error?: string };
      if (!response.ok || typeof data.note !== 'string') throw new Error(data.error || '备注保存失败');
      const notes = await loadPortNotes();
      notes[portFlagKey(node.alias, port.id)] = data.note;
      setSavedNote(data.note);
    } catch (error) { setNoteError(error instanceof Error ? error.message : '备注保存失败'); }
    finally { setSavingNote(false); }
  };
  const total = port.upload + port.download;
  const risk = riskFor(port);
  const displayedIps = showAllIps && allIps ? allIps : port.ips;
  const active = displayedIps.filter((item) => item.online !== false && !item.scanner);
  const activeCount = port.activeIpCount ?? active.length;
  const totalIps = port.totalIps ?? port.ips.length;
  const shown = displayedIps.slice(0, showAllIps ? visibleIpLimit : 3);
  const toggleIps = async () => {
    if (showAllIps && allIps && visibleIpLimit < allIps.length) { setVisibleIpLimit((current) => Math.min(current + 100, allIps.length)); return; }
    if (allIps) { setVisibleIpLimit(100); setShowAllIps(true); return; }
    setLoadingIps(true); setIpError('');
    try {
      const response = await fetch(`/api/xui/port-ips?alias=${encodeURIComponent(node.alias)}&port=${port.port}`);
      const data = await response.json() as { ips?: ClientIp[]; error?: string };
      if (!response.ok || !data.ips) throw new Error(data.error || 'IP 记录读取失败');
      setAllIps(data.ips); setVisibleIpLimit(100); setShowAllIps(true);
    } catch (error) { setIpError(error instanceof Error ? error.message : 'IP 记录读取失败'); }
    finally { setLoadingIps(false); }
  };
  return <div className={`border-t first:border-t-0 ${risk.level >= 3 ? 'border-rose-400/15 bg-rose-400/[.018]' : 'border-white/6'}`}><div className="grid gap-3 px-4 py-4 sm:px-5 lg:grid-cols-[90px_100px_120px_minmax(360px,1fr)_160px_210px] lg:items-center lg:gap-3">
    <DataCell label="端口"><span className="font-mono text-base font-semibold text-cyan-200">{port.port}</span></DataCell>
    <DataCell label="状态"><Badge className={port.enabled ? 'bg-emerald-400/12 text-emerald-300' : 'bg-slate-600/20 text-slate-400'}>{port.enabled ? '已启用' : '已停用'}</Badge></DataCell>
    <DataCell label="累计流量"><span className="text-base font-medium text-slate-200">{formatTraffic(total)}</span></DataCell>
    <div className="min-w-0"><div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500"><span className={activeCount >= 2 ? 'font-semibold text-amber-300' : ''}>当前 {activeCount}</span><span>1小时 {port.recent1h ?? totalIps}</span><span>24小时 {port.recent24h ?? totalIps}</span></div><div className="flex flex-wrap gap-2">{shown.length ? shown.map((item) => <div key={item.ip} className={`min-w-[250px] flex-1 rounded-xl border px-3 py-2.5 ${item.scanner ? 'border-slate-500/20 bg-slate-500/[.035]' : activeCount > 1 ? 'border-amber-400/20 bg-amber-400/[.045]' : 'border-white/8 bg-white/[.03]'}`}><div className="flex items-center gap-2"><Globe2 className={`size-4 shrink-0 ${item.scanner ? 'text-slate-400' : 'text-amber-300'}`} /><p className="min-w-0 flex-1 truncate font-mono text-sm font-medium text-slate-100">{item.ip}</p>{item.scanner && <Badge className="bg-slate-400/12 text-slate-300">扫描 IP · {item.scannedPorts}端口</Badge>}{item.isNew && !item.scanner && <Badge className="bg-violet-400/10 text-violet-300">新</Badge>}</div><div className="mt-2 rounded-md border border-cyan-400/10 bg-cyan-400/[.055] px-2 py-1.5"><p className="flex items-center gap-1.5 truncate text-xs font-medium text-cyan-200"><MapPin className="size-3.5 shrink-0 text-cyan-300" /><span className="text-cyan-400/70">归属</span>{item.location}</p></div><div className="mt-1.5 flex items-start gap-1.5 rounded-md border border-violet-400/10 bg-violet-400/[.045] px-2 py-1.5 text-[11px] leading-4 text-violet-200"><Clock3 className="mt-0.5 size-3.5 shrink-0 text-violet-300" /><div className="min-w-0"><p><span className="text-violet-400/70">首次</span> {formatSeenAt(item.firstSeen)}</p><p><span className="text-violet-400/70">最后</span> {item.online ? '当前在线' : formatSeenAt(item.lastSeen)}</p></div></div></div>) : <div className="rounded-lg border border-dashed border-white/8 px-3 py-2 text-sm text-slate-600">最近没有活跃 IP</div>}{totalIps > 3 && (!showAllIps || (allIps && shown.length < allIps.length)) && <Button type="button" size="sm" variant="ghost" onClick={toggleIps} disabled={loadingIps} aria-expanded={showAllIps} className="self-center text-slate-400 hover:bg-white/5 hover:text-cyan-200">{loadingIps ? '读取中…' : showAllIps && allIps ? `继续显示 ${Math.min(100, allIps.length - shown.length)} 个` : `展开另外 ${totalIps - 3} 个 IP`}<ChevronDown className="size-4" /></Button>}{showAllIps && <Button type="button" size="sm" variant="ghost" onClick={() => setShowAllIps(false)} className="self-center text-slate-400 hover:bg-white/5 hover:text-cyan-200">收起 IP<ChevronDown className="size-4 rotate-180" /></Button>}{ipError && <p role="alert" className="self-center text-sm text-rose-300">{ipError}</p>}</div></div>
    <div><Badge variant="outline" className={`border ${risk.tone}`}>{risk.label}</Badge><p className="mt-2 text-xs leading-5 text-slate-500">{risk.reason}</p>{(port.overlapMinutes || 0) > 0 && <p className="text-xs text-slate-600">重叠 {port.overlapMinutes} 分钟</p>}</div>
    <div className="flex flex-wrap items-center justify-end gap-1.5"><Button size="sm" variant="ghost" onClick={() => setPortFlag(node.alias, port.id, 'observing')} className={port.observing ? 'bg-violet-400/10 text-violet-300' : 'text-slate-400'}><Eye className="size-3.5" />观察</Button><Button size="sm" variant="ghost" onClick={() => setPortFlag(node.alias, port.id, 'trusted')} className={port.trusted ? 'bg-sky-400/10 text-sky-300' : 'text-slate-400'}><ShieldCheck className="size-3.5" />可信</Button><Button size="sm" variant="ghost" onClick={() => setMessage(`${node.alias}-${port.port} 的 7 天记录将在采集器接入后显示。`)} className="text-slate-400"><History className="size-3.5" />7天</Button><Switch checked={port.enabled} onCheckedChange={(next) => setPending({ alias: node.alias, id: port.id, next })} aria-label={`${port.enabled ? '停用' : '启用'} ${node.alias} 端口 ${port.port}`} /></div>
    <div className="space-y-2 lg:col-start-6"><Textarea value={note} onChange={(event) => setNote(event.target.value)} disabled={!noteLoaded || savingNote} maxLength={2000} rows={2} aria-label={`${node.alias} 端口 ${port.port} 处理备注`} placeholder={noteLoaded ? '输入处理备注…' : '正在读取备注…'} className="min-h-16 border-white/15 bg-[#071019] text-sm text-slate-100 placeholder:text-slate-500" /><div className="flex items-center justify-between gap-2"><span className="text-xs text-slate-400" role="status">{noteLoaded && (note === savedNote ? '已保存' : '未保存')}</span><Button size="sm" onClick={saveNote} disabled={!noteLoaded || savingNote || note === savedNote} className="bg-cyan-400 text-slate-950 hover:bg-cyan-300">{savingNote ? '保存中' : '保存备注'}</Button></div>{noteError && <p role="alert" className="text-sm text-rose-300">{noteError}</p>}</div>
  </div></div>;
}

function DataCell({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="flex items-center justify-between lg:block"><span className="lg:hidden metric-label">{label}</span>{children}</div>;
}
