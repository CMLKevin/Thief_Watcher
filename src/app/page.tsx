"use client";

import JSZip from "jszip";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type Label = {
  address: string;
  label?: string | null;
  type?: string;
  source?: string;
  confidence?: string;
};

type EventRow = {
  id: string;
  time: string;
  severity: string;
  message: string;
  token?: string;
  amount?: number;
  counterparty?: string;
  counterpartyLabel?: Label;
  txHash?: string;
  direction?: string;
};

type StatusPayload = {
  running: boolean;
  thiefWallet: string;
  currentBlock: number | null;
  lastCheckedBlock: number | null;
  nonce: number | null;
  maticBalance: number;
  tokenBalances: { USDC?: number; "USDC.e"?: number };
  eventCount: number;
  lastPollAt: string | null;
  lastError: string | null;
  webhookUrl: string | null;
  rpcPool: string[];
};

type TraceNode = {
  address: string;
  label: Label;
};

type TraceEdge = {
  from: string;
  to: string;
  token: string;
  amount: number;
  txHash: string;
  hop: number;
};

type TraceGraph = {
  nodeCount: number;
  edgeCount: number;
  hops: number;
  fromBlock: number;
  toBlock: number;
  nodes: TraceNode[];
  edges: TraceEdge[];
  exposures: Record<string, number>;
};

type ProfileResult = {
  address: string;
  label: Label;
  balances: { MATIC: number; nonce: number; USDC: number; "USDC.e": number };
  recentTransfers: Array<{
    direction: string;
    token: string;
    amount: number;
    counterparty: string;
    counterpartyLabel?: Label;
    txHash: string;
  }>;
  profileHint?: { title?: string | null };
};

const short = (value?: string | null, left = 8, right = 6) => {
  if (!value) return "-";
  if (value.length <= left + right + 3) return value;
  return `${value.slice(0, left)}...${value.slice(-right)}`;
};

const num = (value: unknown, digits = 6) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return "-";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits });
};

const sevClass = (sev: string) => {
  const s = (sev || "info").toLowerCase();
  if (s === "critical" || s === "error") return "critical";
  if (s === "warning") return "warn";
  if (s === "ok") return "ok";
  return "info";
};

export default function HomePage() {
  const [status, setStatus] = useState<StatusPayload | null>(null);
  const [intelSummary, setIntelSummary] = useState<{ totalTags?: number; types?: Record<string, number> } | null>(null);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [tags, setTags] = useState<Array<Record<string, unknown>>>([]);
  const [profile, setProfile] = useState<ProfileResult | null>(null);
  const [trace, setTrace] = useState<TraceGraph | null>(null);
  const [playbook, setPlaybook] = useState<Record<string, unknown> | null>(null);
  const [packet, setPacket] = useState<{
    packetId: string;
    generatedAt: string;
    summary: Record<string, unknown>;
    artifacts: Record<string, string>;
  } | null>(null);

  const [message, setMessage] = useState("Loading");
  const [messageLevel, setMessageLevel] = useState("info");
  const [busy, setBusy] = useState(false);

  const [eventSeverity, setEventSeverity] = useState("");
  const [eventDirection, setEventDirection] = useState("");
  const [eventToken, setEventToken] = useState("");
  const [eventQ, setEventQ] = useState("");
  const [eventLimit, setEventLimit] = useState(220);

  const [tagQ, setTagQ] = useState("");
  const [tagType, setTagType] = useState("");

  const [tagAddress, setTagAddress] = useState("");
  const [tagLabel, setTagLabel] = useState("");
  const [tagKind, setTagKind] = useState("custom");
  const [tagSource, setTagSource] = useState("manual");
  const [tagNotes, setTagNotes] = useState("");

  const [profileAddress, setProfileAddress] = useState("0xF5eF5Ac6B71373Be7af86eBD00Af44794CE3074E");
  const [profileWindow, setProfileWindow] = useState(50000);

  const [traceSeeds, setTraceSeeds] = useState(
    "0x3ADdC290C324d45A8E4fa8Ef129054d15a8590eF\n0xF5eF5Ac6B71373Be7af86eBD00Af44794CE3074E",
  );
  const [traceHops, setTraceHops] = useState(2);
  const [traceEdges, setTraceEdges] = useState(1200);
  const [traceFrom, setTraceFrom] = useState(83285000);
  const [traceTo, setTraceTo] = useState<number | "">("");

  const [webhook, setWebhook] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);

  const [packetCaseId, setPacketCaseId] = useState("polymarket-insider-drain-2026");
  const [packetAnalyst, setPacketAnalyst] = useState("Incident Response Team");
  const [packetCex, setPacketCex] = useState("Target Exchange");
  const [packetNotes, setPacketNotes] = useState("");

  const [graphZoom, setGraphZoom] = useState(1);
  const [graphOffset, setGraphOffset] = useState({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState<TraceNode | null>(null);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const positionsRef = useRef<Record<string, { x: number; y: number }>>({});

  const apiGet = useCallback(async (url: string) => {
    const res = await fetch(url, { cache: "no-store" });
    const data = await res.json();
    if (!res.ok || data.ok === false) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  }, []);

  const apiPost = useCallback(async (url: string, body: unknown) => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
    });
    const data = await res.json();
    if (!res.ok || data.ok === false) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  }, []);

  const toast = useCallback((msg: string, level = "info") => {
    setMessage(msg);
    setMessageLevel(level);
  }, []);

  const fetchStatus = useCallback(async () => {
    const data = await apiGet("/api/status");
    setStatus(data.status);
    setIntelSummary(data.intelSummary || null);
    setWebhook(data.status?.webhookUrl || "");
  }, [apiGet]);

  const fetchEvents = useCallback(async () => {
    const params = new URLSearchParams();
    params.set("limit", String(eventLimit));
    if (eventSeverity) params.set("severity", eventSeverity);
    if (eventDirection) params.set("direction", eventDirection);
    if (eventToken) params.set("token", eventToken);
    if (eventQ.trim()) params.set("q", eventQ.trim());

    const data = await apiGet(`/api/events?${params.toString()}`);
    setEvents(data.events || []);
  }, [apiGet, eventDirection, eventLimit, eventQ, eventSeverity, eventToken]);

  const fetchTags = useCallback(async () => {
    const params = new URLSearchParams();
    if (tagQ.trim()) params.set("q", tagQ.trim());
    if (tagType) params.set("type", tagType);

    const query = params.toString();
    const data = await apiGet(`/api/tags${query ? `?${query}` : ""}`);
    setTags(data.tags || []);
  }, [apiGet, tagQ, tagType]);

  const fetchPlaybook = useCallback(async () => {
    const data = await apiGet("/api/playbook");
    setPlaybook(data.playbook || null);
  }, [apiGet]);

  const refreshAll = useCallback(async () => {
    setBusy(true);
    try {
      await Promise.all([fetchStatus(), fetchEvents(), fetchTags()]);
      if (!playbook) await fetchPlaybook();
      toast("Console refreshed", "info");
    } catch (error) {
      toast(String(error), "critical");
    } finally {
      setBusy(false);
    }
  }, [fetchEvents, fetchPlaybook, fetchStatus, fetchTags, playbook, toast]);

  useEffect(() => {
    void refreshAll();
  }, [refreshAll]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => {
      void Promise.all([fetchStatus(), fetchEvents()]).catch((error) =>
        toast(String(error), "critical"),
      );
    }, 6500);
    return () => clearInterval(id);
  }, [autoRefresh, fetchEvents, fetchStatus, toast]);

  const statusPillClass = useMemo(() => {
    if (!status) return "info";
    return status.running ? "ok" : "warn";
  }, [status]);

  const runAction = useCallback(
    async (action: "start" | "stop" | "tick") => {
      try {
        setBusy(true);
        const path =
          action === "start"
            ? "/api/control/start"
            : action === "stop"
              ? "/api/control/stop"
              : "/api/control/tick";
        await apiPost(path, {});
        await refreshAll();
        toast(
          action === "start"
            ? "Watcher started"
            : action === "stop"
              ? "Watcher stopped"
              : "Manual tick completed",
          action === "stop" ? "warn" : "ok",
        );
      } catch (error) {
        toast(String(error), "critical");
      } finally {
        setBusy(false);
      }
    },
    [apiPost, refreshAll, toast],
  );

  const handleAddTag = useCallback(async () => {
    try {
      if (!tagAddress.trim() || !tagLabel.trim()) {
        toast("Tag address and label are required", "critical");
        return;
      }
      await apiPost("/api/tags", {
        address: tagAddress.trim(),
        label: tagLabel.trim(),
        type: tagKind.trim() || "custom",
        source: tagSource.trim() || "manual",
        notes: tagNotes.trim(),
      });
      setTagAddress("");
      setTagLabel("");
      setTagNotes("");
      await Promise.all([fetchTags(), fetchStatus()]);
      toast("Tag saved", "ok");
    } catch (error) {
      toast(String(error), "critical");
    }
  }, [apiPost, fetchStatus, fetchTags, tagAddress, tagKind, tagLabel, tagNotes, tagSource, toast]);

  const handleProfile = useCallback(async () => {
    try {
      const data = await apiPost("/api/profile", {
        address: profileAddress.trim(),
        window: profileWindow,
      });
      setProfile(data.profile || null);
      toast("Profile loaded", "ok");
    } catch (error) {
      toast(String(error), "critical");
    }
  }, [apiPost, profileAddress, profileWindow, toast]);

  const handleTrace = useCallback(async () => {
    try {
      const seeds = traceSeeds
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const data = await apiPost("/api/trace", {
        seeds,
        hops: traceHops,
        maxEdges: traceEdges,
        fromBlock: Number(traceFrom) || undefined,
        toBlock: traceTo === "" ? undefined : Number(traceTo),
      });
      setTrace(data.graph || null);
      setSelectedNode(null);
      toast("Trace graph built", "ok");
    } catch (error) {
      toast(String(error), "critical");
    }
  }, [apiPost, toast, traceEdges, traceFrom, traceHops, traceSeeds, traceTo]);

  const handleWebhook = useCallback(
    async (value: string) => {
      try {
        await apiPost("/api/webhook", { url: value });
        setWebhook(value);
        await fetchStatus();
        toast(value ? "Webhook updated" : "Webhook cleared", value ? "ok" : "warn");
      } catch (error) {
        toast(String(error), "critical");
      }
    },
    [apiPost, fetchStatus, toast],
  );

  const handlePacket = useCallback(async () => {
    try {
      const seeds = traceSeeds
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const data = await apiPost("/api/escalation-packet", {
        caseId: packetCaseId,
        analyst: packetAnalyst,
        cexName: packetCex,
        notes: packetNotes,
        victimWallet: seeds[0],
        suspectWallet: status?.thiefWallet,
        seeds,
        hops: traceHops,
        maxEdges: traceEdges,
        fromBlock: Number(traceFrom) || undefined,
        toBlock: traceTo === "" ? undefined : Number(traceTo),
      });
      setPacket(data);
      toast("Escalation packet generated", "ok");
    } catch (error) {
      toast(String(error), "critical");
    }
  }, [
    apiPost,
    packetAnalyst,
    packetCaseId,
    packetCex,
    packetNotes,
    status?.thiefWallet,
    toast,
    traceEdges,
    traceFrom,
    traceHops,
    traceSeeds,
    traceTo,
  ]);

  const downloadJson = useCallback((name: string, payload: unknown) => {
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }, []);

  const downloadPacketZip = useCallback(async () => {
    if (!packet) {
      toast("No packet generated yet", "warn");
      return;
    }

    const zip = new JSZip();
    for (const [name, content] of Object.entries(packet.artifacts || {})) {
      zip.file(name, content);
    }

    const blob = await zip.generateAsync({ type: "blob" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${packet.packetId}_cex_bundle.zip`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }, [packet, toast]);

  const metricItems = useMemo(
    () => [
      ["Current Block", status?.currentBlock ?? "-"],
      ["Last Checked", status?.lastCheckedBlock ?? "-"],
      ["Nonce", status?.nonce ?? "-"],
      ["MATIC", num(status?.maticBalance, 8)],
      ["USDC", num(status?.tokenBalances?.USDC, 6)],
      ["USDC.e", num(status?.tokenBalances?.["USDC.e"], 6)],
      ["Total Events", status?.eventCount ?? "-"],
      ["Last Poll", status?.lastPollAt || "-"],
      ["Tag Count", intelSummary?.totalTags ?? "-"],
      ["RPC Pool", status?.rpcPool?.length ?? "-"],
    ],
    [intelSummary?.totalTags, status],
  );

  const graphColors = useMemo(
    () => ({
      suspect: "#ff5b7f",
      victim: "#4fa6ff",
      bridge: "#f8be4e",
      cex: "#36d986",
      dex: "#b494ff",
      mixer: "#ff5b7f",
      protocol: "#61e5d7",
      unknown: "#8fa8d1",
      default: "#8fa8d1",
    }),
    [],
  );

  const drawTrace = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || !trace) return;

    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.floor(rect.width * dpr);
    canvas.height = Math.floor(rect.height * dpr);
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const width = rect.width;
    const height = rect.height;

    if (!Object.keys(positionsRef.current).length && trace.nodes.length) {
      const nodes = trace.nodes;
      const centerX = width / 2;
      const centerY = height / 2;

      const depth = new Map<string, number>();
      for (const seed of trace.nodes.slice(0, 4)) {
        depth.set(seed.address, 0);
      }

      let changed = true;
      while (changed) {
        changed = false;
        for (const edge of trace.edges) {
          const fromDepth = depth.get(edge.from);
          if (fromDepth === undefined) continue;
          const toDepth = fromDepth + 1;
          if (!depth.has(edge.to) || (depth.get(edge.to) ?? 999) > toDepth) {
            depth.set(edge.to, toDepth);
            changed = true;
          }
        }
      }

      nodes.forEach((node, i) => {
        const ring = Math.min(4, depth.get(node.address) ?? (i % 4));
        const angle = (Math.PI * 2 * i) / Math.max(1, nodes.length);
        const radius = 45 + ring * 52 + (i % 3) * 9;
        positionsRef.current[node.address] = {
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
        };
      });
    }

    ctx.clearRect(0, 0, width, height);
    ctx.save();
    ctx.translate(graphOffset.x, graphOffset.y);
    ctx.scale(graphZoom, graphZoom);

    for (const edge of trace.edges) {
      const a = positionsRef.current[edge.from];
      const b = positionsRef.current[edge.to];
      if (!a || !b) continue;
      ctx.strokeStyle = "rgba(143, 168, 209, 0.28)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }

    for (const node of trace.nodes) {
      const p = positionsRef.current[node.address];
      if (!p) continue;
      const nodeType = String(node.label?.type || "unknown");
      const color = graphColors[nodeType as keyof typeof graphColors] || graphColors.default;
      const isSelected = selectedNode?.address === node.address;
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(p.x, p.y, isSelected ? 8 : 5.4, 0, Math.PI * 2);
      ctx.fill();
      if (isSelected) {
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 1.6;
        ctx.stroke();
      }
    }

    ctx.restore();
  }, [graphColors, graphOffset.x, graphOffset.y, graphZoom, selectedNode?.address, trace]);

  useEffect(() => {
    positionsRef.current = {};
    setGraphZoom(1);
    setGraphOffset({ x: 0, y: 0 });
  }, [trace?.nodeCount, trace?.edgeCount]);

  useEffect(() => {
    drawTrace();
  }, [drawTrace]);

  const handleCanvasClick = useCallback(
    (ev: React.MouseEvent<HTMLCanvasElement>) => {
      if (!trace) return;
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const x = (ev.clientX - rect.left - graphOffset.x) / graphZoom;
      const y = (ev.clientY - rect.top - graphOffset.y) / graphZoom;

      let closest: { node: TraceNode; dist: number } | null = null;
      for (const node of trace.nodes) {
        const p = positionsRef.current[node.address];
        if (!p) continue;
        const d = Math.hypot(p.x - x, p.y - y);
        if (d <= 12 && (!closest || d < closest.dist)) {
          closest = { node, dist: d };
        }
      }
      setSelectedNode(closest?.node || null);
    },
    [graphOffset.x, graphOffset.y, graphZoom, trace],
  );

  const selectedNodeConnections = useMemo(() => {
    if (!trace || !selectedNode) return [];
    return trace.edges.filter(
      (e) => e.from === selectedNode.address || e.to === selectedNode.address,
    );
  }, [selectedNode, trace]);

  return (
    <main className="page-shell">
      <section className="panel hero">
        <div className="hero-top">
          <div>
            <h1>Thief Watcher Command Center</h1>
            <div className="subtitle">
              Full-spectrum blockchain incident response for wallet
              <span className="mono"> {short(status?.thiefWallet, 10, 10)}</span>
            </div>
          </div>
          <span className={`pill ${statusPillClass}`}>{status?.running ? "Watcher Running" : "Watcher Stopped"}</span>
        </div>

        <div className="toolbar">
          <button className="btn btn-primary" onClick={() => void runAction("start")} disabled={busy}>
            Start Watcher
          </button>
          <button className="btn" onClick={() => void runAction("stop")} disabled={busy}>
            Stop Watcher
          </button>
          <button className="btn" onClick={() => void runAction("tick")} disabled={busy}>
            Manual Tick
          </button>
          <button className="btn" onClick={() => void refreshAll()} disabled={busy}>
            Refresh
          </button>
          <label className="mono" style={{ color: "var(--muted)" }}>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              style={{ marginRight: 6 }}
            />
            Auto 6.5s
          </label>
        </div>

        <div className="controls">
          <span className="mono">Webhook: {status?.webhookUrl || "(not set)"}</span>
          <span className="mono">Last error: {status?.lastError || "none"}</span>
          <span className={`pill ${sevClass(messageLevel)}`}>{message}</span>
        </div>
      </section>

      <section className="grid-metrics">
        {metricItems.map(([k, v]) => (
          <div className="metric" key={String(k)}>
            <div className="k">{k}</div>
            <div className="v mono">{String(v)}</div>
          </div>
        ))}
      </section>

      <section className="row-grid row-2">
        <div className="panel">
          <div className="subhead">Live Event Stream</div>
          <div className="controls">
            <select className="select w-120" value={eventSeverity} onChange={(e) => setEventSeverity(e.target.value)}>
              <option value="">All Severity</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="error">Error</option>
              <option value="info">Info</option>
            </select>
            <select className="select w-120" value={eventDirection} onChange={(e) => setEventDirection(e.target.value)}>
              <option value="">All Direction</option>
              <option value="out">Outgoing</option>
              <option value="in">Incoming</option>
            </select>
            <select className="select w-120" value={eventToken} onChange={(e) => setEventToken(e.target.value)}>
              <option value="">All Token</option>
              <option value="USDC">USDC</option>
              <option value="USDC.e">USDC.e</option>
            </select>
            <input className="input w-220" value={eventQ} onChange={(e) => setEventQ(e.target.value)} placeholder="tx/counterparty/search" />
            <input
              className="input w-120"
              type="number"
              value={eventLimit}
              min={1}
              max={1000}
              onChange={(e) => setEventLimit(Number(e.target.value || 150))}
            />
            <button className="btn" onClick={() => void fetchEvents()}>
              Apply
            </button>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Time</th>
                  <th>Message</th>
                  <th>Amount</th>
                  <th>Counterparty</th>
                  <th>Tx</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="mono">
                      No matching events.
                    </td>
                  </tr>
                ) : (
                  events.map((ev) => (
                    <tr key={ev.id}>
                      <td>
                        <span className={`pill ${sevClass(ev.severity)}`}>{ev.severity}</span>
                      </td>
                      <td className="mono">{ev.time || "-"}</td>
                      <td>{ev.message}</td>
                      <td className="mono">
                        {ev.amount !== undefined ? `${num(ev.amount)} ${ev.token || ""}` : "-"}
                      </td>
                      <td className="mono" title={ev.counterparty || ""}>
                        {short(ev.counterparty)}
                        {ev.counterpartyLabel?.type ? ` [${ev.counterpartyLabel.type}]` : ""}
                      </td>
                      <td className="mono">
                        {ev.txHash ? (
                          <a href={`https://polygon.blockscout.com/tx/${ev.txHash}`} target="_blank" rel="noreferrer">
                            {short(ev.txHash, 10, 8)}
                          </a>
                        ) : (
                          "-"
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="subhead">Intel Tags</div>
          <div className="controls">
            <input className="input w-220" value={tagQ} onChange={(e) => setTagQ(e.target.value)} placeholder="search tags" />
            <select className="select w-140" value={tagType} onChange={(e) => setTagType(e.target.value)}>
              <option value="">All Types</option>
              <option value="suspect">suspect</option>
              <option value="bridge">bridge</option>
              <option value="cex">cex</option>
              <option value="dex">dex</option>
              <option value="mixer">mixer</option>
              <option value="protocol">protocol</option>
              <option value="custom">custom</option>
            </select>
            <button className="btn" onClick={() => void fetchTags()}>
              Reload
            </button>
          </div>

          <div className="kpi-row">
            {Object.entries(intelSummary?.types || {}).map(([type, count]) => (
              <span key={type} className="kpi mono">
                {type}: {String(count)}
              </span>
            ))}
          </div>

          <div className="table-wrap" style={{ maxHeight: 260 }}>
            <table>
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Label</th>
                  <th>Type</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {tags.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="mono">
                      No tags
                    </td>
                  </tr>
                ) : (
                  tags.slice(0, 500).map((tag) => (
                    <tr key={String(tag.address)}>
                      <td className="mono" title={String(tag.address || "")}>{short(String(tag.address || ""))}</td>
                      <td>{String(tag.label || "-")}</td>
                      <td>
                        <span className={`pill ${sevClass(String(tag.type || "info") === "mixer" ? "critical" : String(tag.type || "info") === "cex" ? "warning" : "info")}`}>
                          {String(tag.type || "unknown")}
                        </span>
                      </td>
                      <td className="mono">{String(tag.source || "-")}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="subhead" style={{ marginTop: 12 }}>
            Add Custom Tag
          </div>
          <div className="controls">
            <input className="input w-full mono" value={tagAddress} onChange={(e) => setTagAddress(e.target.value)} placeholder="0x..." />
          </div>
          <div className="controls">
            <input className="input w-220" value={tagLabel} onChange={(e) => setTagLabel(e.target.value)} placeholder="Label" />
            <input className="input w-140" value={tagKind} onChange={(e) => setTagKind(e.target.value)} placeholder="type" />
            <input className="input w-140" value={tagSource} onChange={(e) => setTagSource(e.target.value)} placeholder="source" />
          </div>
          <textarea className="textarea" value={tagNotes} onChange={(e) => setTagNotes(e.target.value)} placeholder="analyst notes" />
          <div className="controls" style={{ marginTop: 8 }}>
            <button className="btn btn-primary" onClick={() => void handleAddTag()}>
              Save Tag
            </button>
          </div>
        </div>
      </section>

      <section className="row-grid row-2">
        <div className="panel">
          <div className="subhead">Address Profiler</div>
          <div className="controls">
            <input className="input w-full mono" value={profileAddress} onChange={(e) => setProfileAddress(e.target.value)} placeholder="0x..." />
          </div>
          <div className="controls">
            <input className="input w-160" type="number" min={500} max={250000} value={profileWindow} onChange={(e) => setProfileWindow(Number(e.target.value || 50000))} />
            <button className="btn btn-primary" onClick={() => void handleProfile()}>
              Profile Address
            </button>
          </div>

          <div className="kpi-row">
            <span className="kpi mono">type: {profile?.label?.type || "-"}</span>
            <span className="kpi mono">nonce: {profile?.balances?.nonce ?? "-"}</span>
            <span className="kpi mono">MATIC: {num(profile?.balances?.MATIC, 8)}</span>
            <span className="kpi mono">USDC: {num(profile?.balances?.USDC, 6)}</span>
            <span className="kpi mono">USDC.e: {num(profile?.balances?.["USDC.e"], 6)}</span>
          </div>

          <div className="subtitle" style={{ marginBottom: 8 }}>
            {profile
              ? `Profile hint: ${profile.profileHint?.title || "none"}`
              : "No profile loaded"}
          </div>

          <div className="table-wrap" style={{ maxHeight: 280 }}>
            <table>
              <thead>
                <tr>
                  <th>Dir</th>
                  <th>Token</th>
                  <th>Amount</th>
                  <th>Counterparty</th>
                  <th>Type</th>
                  <th>Tx</th>
                </tr>
              </thead>
              <tbody>
                {!profile || profile.recentTransfers.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="mono">
                      No transfer rows
                    </td>
                  </tr>
                ) : (
                  profile.recentTransfers.slice(0, 140).map((t) => (
                    <tr key={`${t.txHash}:${t.counterparty}:${t.amount}`}>
                      <td>{t.direction}</td>
                      <td>{t.token}</td>
                      <td className="mono">{num(t.amount)}</td>
                      <td className="mono" title={t.counterparty}>
                        {short(t.counterparty)}
                      </td>
                      <td>{t.counterpartyLabel?.type || "unknown"}</td>
                      <td className="mono">
                        <a href={`https://polygon.blockscout.com/tx/${t.txHash}`} target="_blank" rel="noreferrer">
                          {short(t.txHash, 10, 8)}
                        </a>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="subhead">Trace Graph Explorer</div>
          <textarea className="textarea" value={traceSeeds} onChange={(e) => setTraceSeeds(e.target.value)} placeholder="seed addresses" />
          <div className="controls">
            <input className="input w-120" type="number" min={1} max={5} value={traceHops} onChange={(e) => setTraceHops(Number(e.target.value || 2))} />
            <input className="input w-140" type="number" min={100} max={3000} value={traceEdges} onChange={(e) => setTraceEdges(Number(e.target.value || 1200))} />
            <input className="input w-140" type="number" value={traceFrom} onChange={(e) => setTraceFrom(Number(e.target.value || 0))} />
            <input className="input w-140" type="number" value={traceTo} onChange={(e) => setTraceTo(e.target.value ? Number(e.target.value) : "")} placeholder="to block" />
          </div>
          <div className="controls">
            <button className="btn btn-primary" onClick={() => void handleTrace()}>
              Build Graph
            </button>
            <button className="btn" onClick={() => setGraphZoom((z) => Math.min(2.6, z + 0.12))}>
              Zoom +
            </button>
            <button className="btn" onClick={() => setGraphZoom((z) => Math.max(0.35, z - 0.12))}>
              Zoom -
            </button>
            <button className="btn" onClick={() => { setGraphZoom(1); setGraphOffset({ x: 0, y: 0 }); }}>
              Reset View
            </button>
            <button className="btn" onClick={() => downloadJson(`trace_graph_${Date.now()}.json`, trace || {})}>
              Export JSON
            </button>
          </div>

          <div className="kpi-row">
            <span className="kpi mono">nodes: {trace?.nodeCount ?? 0}</span>
            <span className="kpi mono">edges: {trace?.edgeCount ?? 0}</span>
            <span className="kpi mono">cex: {trace?.exposures?.cex ?? 0}</span>
            <span className="kpi mono">dex: {trace?.exposures?.dex ?? 0}</span>
            <span className="kpi mono">mixer: {trace?.exposures?.mixer ?? 0}</span>
            <span className="kpi mono">bridge: {trace?.exposures?.bridge ?? 0}</span>
          </div>

          <div className="canvas-wrap">
            <canvas ref={canvasRef} id="traceCanvas" onClick={handleCanvasClick} />
          </div>

          <div className="controls" style={{ marginTop: 8 }}>
            <button className="btn" onClick={() => setGraphOffset((o) => ({ ...o, y: o.y - 18 }))}>Pan Up</button>
            <button className="btn" onClick={() => setGraphOffset((o) => ({ ...o, y: o.y + 18 }))}>Pan Down</button>
            <button className="btn" onClick={() => setGraphOffset((o) => ({ ...o, x: o.x - 18 }))}>Pan Left</button>
            <button className="btn" onClick={() => setGraphOffset((o) => ({ ...o, x: o.x + 18 }))}>Pan Right</button>
          </div>

          <div className="table-wrap" style={{ maxHeight: 220, marginTop: 8 }}>
            <table>
              <thead>
                <tr>
                  <th>Hop</th>
                  <th>From</th>
                  <th>To</th>
                  <th>Token</th>
                  <th>Amount</th>
                  <th>Tx</th>
                </tr>
              </thead>
              <tbody>
                {!trace || trace.edges.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="mono">
                      No graph edges
                    </td>
                  </tr>
                ) : (
                  trace.edges.slice(0, 150).map((edge) => (
                    <tr key={`${edge.txHash}:${edge.from}:${edge.to}`}>
                      <td>{edge.hop}</td>
                      <td className="mono" title={edge.from}>{short(edge.from)}</td>
                      <td className="mono" title={edge.to}>{short(edge.to)}</td>
                      <td>{edge.token}</td>
                      <td className="mono">{num(edge.amount)}</td>
                      <td className="mono">
                        <a href={`https://polygon.blockscout.com/tx/${edge.txHash}`} target="_blank" rel="noreferrer">
                          {short(edge.txHash, 10, 8)}
                        </a>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {selectedNode ? (
            <div className="panel" style={{ marginTop: 8, padding: 10, background: "#0d1a34" }}>
              <div className="subhead">Selected Node</div>
              <div className="mono">{selectedNode.address}</div>
              <div>
                type: <span className="good">{selectedNode.label?.type || "unknown"}</span> | label: {selectedNode.label?.label || "(none)"}
              </div>
              <div>connections: {selectedNodeConnections.length}</div>
            </div>
          ) : null}
        </div>
      </section>

      <section className="row-grid row-3">
        <div className="panel">
          <div className="subhead">Recovery Playbook</div>
          <div className="controls">
            <button className="btn btn-primary" onClick={() => void fetchPlaybook()}>
              Refresh Playbook
            </button>
          </div>
          <div className="subtitle">{String(playbook?.objective || "No playbook loaded")}</div>
          <ol className="list">
            {Array.isArray(playbook?.immediateActions)
              ? (playbook?.immediateActions as string[]).map((step) => <li key={step}>{step}</li>)
              : null}
          </ol>
        </div>

        <div className="panel">
          <div className="subhead">Webhook + Exports</div>
          <div className="controls">
            <input className="input w-full" value={webhook} onChange={(e) => setWebhook(e.target.value)} placeholder="https://hooks.slack.com/..." />
          </div>
          <div className="controls">
            <button className="btn btn-primary" onClick={() => void handleWebhook(webhook)}>
              Set Webhook
            </button>
            <button className="btn" onClick={() => void handleWebhook("")}>Clear Webhook</button>
          </div>
          <div className="controls">
            <button className="btn" onClick={() => downloadJson(`state_${Date.now()}.json`, status || {})}>
              Export Status
            </button>
            <button className="btn" onClick={() => downloadJson(`events_${Date.now()}.json`, events)}>
              Export Events
            </button>
          </div>
        </div>

        <div className="panel">
          <div className="subhead">CEX Escalation Bundle</div>
          <div className="controls">
            <input className="input w-full" value={packetCaseId} onChange={(e) => setPacketCaseId(e.target.value)} placeholder="Case ID" />
          </div>
          <div className="controls">
            <input className="input w-full" value={packetAnalyst} onChange={(e) => setPacketAnalyst(e.target.value)} placeholder="Analyst" />
          </div>
          <div className="controls">
            <input className="input w-full" value={packetCex} onChange={(e) => setPacketCex(e.target.value)} placeholder="Target CEX" />
          </div>
          <textarea className="textarea" value={packetNotes} onChange={(e) => setPacketNotes(e.target.value)} placeholder="Escalation notes" />
          <div className="controls">
            <button className="btn btn-primary" onClick={() => void handlePacket()}>
              Generate Packet
            </button>
            <button className="btn" onClick={() => void downloadPacketZip()}>
              Download ZIP
            </button>
          </div>
          {packet ? (
            <div className="kpi-row">
              <span className="kpi mono">packet: {packet.packetId}</span>
              <span className="kpi mono">generated: {packet.generatedAt}</span>
              <span className="kpi mono">files: {Object.keys(packet.artifacts || {}).length}</span>
            </div>
          ) : (
            <div className="subtitle">No escalation bundle generated yet.</div>
          )}
        </div>
      </section>
    </main>
  );
}
