import { useEffect, useRef, useMemo, useState, useCallback } from 'react';
import { MultiGraph } from 'graphology';
import Sigma from 'sigma';
import { Crosshair, Network, SlidersHorizontal, Skull, Target, Check, Shield, X as XIcon } from 'lucide-react';
import { Badge } from './Badge';
import { Legend } from './Legend';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import { getNodeColor, getCvssColor, getConfidenceColor, getScanSourceColor, ROLE_COLORS } from '../utils/colors';
import { HIGH_VALUE_ROLES, formatCvss } from '../utils/format';
import type { GraphResponse, PathsResponse, HostListResponse, ScanSourceOut, VulnOut } from '../types';

interface Props {
  selectedHost: string | null;
  onSelectHost: (ip: string | null) => void;
  onSelectScanSource?: (name: string | null) => void;
  highlightPathIps?: string[] | null;
  onClearPath?: () => void;
  onDataChanged?: () => void;
  onCloseDetail?: () => void;
  refreshKey?: number;
}

interface HostVulnInfo {
  vulnCount: number;
  maxCvss: number;
  hasExploit: boolean;
  isNew: boolean;
  isStale: boolean;
  hasChanges: boolean;
  owned: boolean;
  target: boolean;
  topVulns: VulnOut[];
}

export function GraphCanvas({ selectedHost, onSelectHost, onSelectScanSource, highlightPathIps, onClearPath, onDataChanged, onCloseDetail, refreshKey = 0 }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const sigmaRef = useRef<Sigma | null>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [attackOnly, setAttackOnly] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [filterVulnOnly, setFilterVulnOnly] = useState(false);
  const [filterRoles, setFilterRoles] = useState<Set<string>>(new Set());
  // Filters popover uses the same hover-with-delay pattern as Legend:
  // panel opens on mouse-enter, stays while mouse is on either the
  // trigger or the panel itself, closes 150ms after mouse leaves both.
  // The delay covers the gap the cursor crosses between trigger and
  // panel so the popover doesn't flicker closed mid-travel.
  const filtersCloseTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showFiltersPanel = () => {
    if (filtersCloseTimer.current) {
      clearTimeout(filtersCloseTimer.current);
      filtersCloseTimer.current = null;
    }
    setShowFilters(true);
  };
  const scheduleHideFilters = () => {
    if (filtersCloseTimer.current) clearTimeout(filtersCloseTimer.current);
    filtersCloseTimer.current = setTimeout(() => setShowFilters(false), 150);
  };
  const [contextMenu, setContextMenu] = useState<{
    x: number; y: number; ip: string; owned: boolean; target: boolean;
  } | null>(null);
  // Hard cap on host nodes we render at once. 1500 covers our realistic demo
  // scans (largest ~1500 hosts) while staying inside Sigma's comfortable zone
  // on mid-range laptops. Beyond the cap the backend returns the most
  // interesting rows first (hosts with CVEs, then hosts with identified
  // roles), so the tail that falls off is background `unknown`-role noise.
  // When truncation happens we surface a banner so the operator knows the
  // canvas is not the full picture.
  const GRAPH_HOST_CAP = 1500;
  const { data, loading, error, refetch } = useApi<GraphResponse>(
    () => api.getGraph(GRAPH_HOST_CAP), [],
  );
  const { data: pathsData } = useApi<PathsResponse>(
    () => api.getAttackPaths({ top: 50, include_check: true }),
    [refreshKey],
  );
  const { data: hostsData, refetch: refetchHosts } = useApi<HostListResponse>(
    () => api.getHosts({ limit: GRAPH_HOST_CAP }),
    [refreshKey],
  );
  // Ordered list of scan sources (by first_seen). The index in this list
  // determines the palette colour each scan position paints onto its
  // edges — earliest scan = lime, first pivot = cyan, etc. Sorted on the
  // backend, so re-renders never shuffle colours.
  const { data: scanSourcesData } = useApi<ScanSourceOut[]>(
    () => api.listScanSources(),
    [refreshKey],
  );
  const scanSourceColorMap = useMemo(() => {
    const map = new Map<string, string>();
    if (!scanSourcesData) return map;
    scanSourcesData.forEach((s, i) => map.set(s.name, getScanSourceColor(i)));
    return map;
  }, [scanSourcesData]);

  // Build host vuln lookup from hosts data — stored in ref to avoid graph rebuilds
  const hostVulnMapRef = useRef(new Map<string, HostVulnInfo>());
  const hostVulnMap = useMemo(() => {
    const map = new Map<string, HostVulnInfo>();
    if (!hostsData) return map;
    for (const h of hostsData.hosts) {
      const vulns = h.vulnerabilities;
      const activeVulns = vulns.filter((v) => v.checked_status !== 'false_positive');
      // Sort vulns: highest confidence first, then by CVSS
      const confOrder: Record<string, number> = { confirmed: 0, likely: 1, check: 2 };
      const sorted = [...activeVulns].sort((a, b) => {
        const ca = confOrder[a.confidence] ?? 2;
        const cb = confOrder[b.confidence] ?? 2;
        if (ca !== cb) return ca - cb;
        return (b.cvss || 0) - (a.cvss || 0);
      });
      map.set(h.ip, {
        vulnCount: activeVulns.length,
        maxCvss: activeVulns.length > 0 ? Math.max(...activeVulns.map((v) => v.cvss)) : -1,
        hasExploit: activeVulns.some((v) => v.has_exploit),
        isNew: h.is_new,
        isStale: h.is_stale,
        hasChanges: h.has_changes,
        owned: h.owned,
        target: h.target,
        topVulns: sorted.slice(0, 5),
      });
    }
    hostVulnMapRef.current = map;
    return map;
  }, [hostsData]);

  // Adjacency map over topology edges (everything except IN_SEGMENT).
  // Used by ``findTopologyPath`` to expand each abstract attack step
  // into the chain of edges that physically connect the two endpoints —
  // so a path "scanner → DC01" tints the chain "scanner → gw → DC01"
  // rather than drawing a direct red shortcut on top of the green
  // topology that already shows the real route.
  const topologyAdj = useMemo(() => {
    const adj = new Map<string, string[]>();
    if (!data) return adj;
    for (const e of data.edges) {
      if (e.type === 'IN_SEGMENT') continue;
      const list = adj.get(e.source) || [];
      list.push(e.target);
      adj.set(e.source, list);
    }
    return adj;
  }, [data]);

  const nodeIdSet = useMemo(
    () => new Set(data?.nodes.map((n) => n.id) ?? []),
    [data],
  );

  // Path-node IPs come bare (no host:/source: prefix). The graph node
  // ID depends on whether the renderer kept the scan source as its own
  // node or merged it into a host. Try both and return whichever the
  // canvas knows about.
  const resolveNodeId = useCallback(
    (ip: string): string | null => {
      const h = `host:${ip}`;
      if (nodeIdSet.has(h)) return h;
      const s = `source:${ip}`;
      if (nodeIdSet.has(s)) return s;
      return null;
    },
    [nodeIdSet],
  );

  // BFS along the directed topology adjacency. Returns the ordered list
  // of edge keys ("src->tgt") that connect start to end. Empty array
  // means no path found in this direction.
  const findTopologyPath = useCallback(
    (start: string, end: string): string[] => {
      if (start === end) return [];
      const visited = new Set([start]);
      const queue: Array<[string, string[]]> = [[start, []]];
      while (queue.length) {
        const [node, edgesSoFar] = queue.shift()!;
        const nexts = topologyAdj.get(node) || [];
        for (const n of nexts) {
          if (visited.has(n)) continue;
          const newEdges = [...edgesSoFar, `${node}->${n}`];
          if (n === end) return newEdges;
          visited.add(n);
          queue.push([n, newEdges]);
        }
      }
      return [];
    },
    [topologyAdj],
  );

  // Attack-edge map keyed on topology edge directions ("src->tgt").
  // For every consecutive (src, dst) pair in an attack path we walk the
  // topology and mark each edge on the route as attack-relevant with
  // the target's vuln count. Edges shared between multiple paths take
  // the largest vuln count. The reducer reads this map to tint the
  // topology edges red — no separate synthetic attack edges are drawn,
  // so the visual chain stays single-stroke (no green/red overlap).
  const attackEdgeMap = useMemo(() => {
    const map = new Map<string, number>();
    if (!pathsData) return map;
    for (const path of pathsData.paths) {
      const target = path.nodes[path.nodes.length - 1];
      const vulnCount = target.vulns.length;
      for (let i = 0; i < path.nodes.length - 1; i++) {
        const startId = resolveNodeId(path.nodes[i].ip);
        const endId = resolveNodeId(path.nodes[i + 1].ip);
        if (!startId || !endId) continue;
        const edgeKeys = findTopologyPath(startId, endId);
        for (const ekey of edgeKeys) {
          map.set(ekey, Math.max(map.get(ekey) || 0, vulnCount));
        }
      }
    }
    return map;
  }, [pathsData, resolveNodeId, findTopologyPath]);

  const graph = useMemo(() => {
    if (!data || data.nodes.length === 0) return null;

    const g = new MultiGraph();

    // Skip segment nodes entirely
    for (const node of data.nodes) {
      if (node.type === 'segment') continue;

      const role = node.properties.role as string | undefined;
      const roleUpper = (role || '').toUpperCase();
      const ip = node.properties.ip as string || node.properties.name as string || '';
      const isScanSource = node.type === 'scan_source' || node.properties.is_scan_source === true;
      // Hosts with zero services are "incomplete" — could be a traceroute
      // hop we haven't scanned yet, a firewalled target with no open ports,
      // or anything in between. Render them visually subordinate (small
      // dim gray) so the operator instantly sees what's actionable vs
      // what's a stub waiting for a follow-up scan.
      //
      // Standalone scan-source nodes (operator's external box) are
      // intentionally serviceless — they don't get the "incomplete"
      // treatment. They're command-center nodes, not under-enumerated
      // targets. Red color + size 8 makes them prominent at the start
      // of the kill chain.
      const serviceCount = (node.properties.service_count as number) ?? 0;
      const isIncomplete = node.type === 'host' && serviceCount === 0;
      const color = isIncomplete ? '#6b7280' : getNodeColor(node.type, role);

      // Base sizing: vuln-based sizing applied in nodeReducer
      let size = node.type === 'host' ? 8 : 5;
      if (isIncomplete) {
        // Hops (zero-service hosts) — sized so they're visible at typical
        // zoom levels and the hostname label stays legible, but still
        // clearly subordinate to scanned hosts (8) and high-value role
        // hosts (10). Going below 5 made gateway / firewall nodes look
        // like noise; 6 is the smallest size that keeps both the dot
        // and the label readable at standard pan-zoom.
        size = 6;
      } else if (node.type === 'scan_source') {
        // Standalone scan sources: visible command-center node, not a
        // tiny incomplete-host dot. ``isScanSource`` also fires for
        // pivot-merged hosts, but those go through the host branch.
        size = 8;
      } else if (node.type === 'host' && HIGH_VALUE_ROLES.has(roleUpper)) {
        size = 10;
      }

      g.addNode(node.id, {
        label: node.label,
        color,
        size,
        nodeType: node.type,
        role: role || '',
        ip,
        isScanSource: isScanSource,
        isIncomplete,
        zIndex: isScanSource ? 100 : isIncomplete ? 0 : 1,
      });
    }

    // Topology edges: thin, source-coloured — skip IN_SEGMENT
    // (hosts-to-segment clutter the canvas, segments are hidden from UI
    // anyway). Edge colour comes from the scan source that observed the
    // hop: scanSourceColorMap looks up the source name (carried in the
    // edge's ``properties.scan_source`` from the API) and returns the
    // palette colour for that source's index. Edges without a known
    // source fall back to a dim default. The edgeReducer can still
    // override this with attack-chain red on top.
    for (const edge of data.edges) {
      if (edge.type === 'IN_SEGMENT') continue;
      if (g.hasNode(edge.source) && g.hasNode(edge.target)) {
        const edgeKey = `topo:${edge.source}->${edge.target}`;
        if (!g.hasEdge(edgeKey)) {
          const scanSource = edge.properties?.scan_source as string | undefined;
          const baseColor = (scanSource && scanSourceColorMap.get(scanSource)) || '#22c55e18';
          g.addEdgeWithKey(edgeKey, edge.source, edge.target, {
            type: 'arrow',
            // Default edge width tuned so the kill chain stays readable
            // at zoom-out (where 0.8px collapsed into the canvas) without
            // overwhelming small graphs (where 2+ looked cartoonish).
            // 1.4 keeps a clear 1.8x ratio against path-highlight (2.5),
            // so the user-clicked path still pops above default chains.
            size: 1.4,
            color: baseColor,
            edgeType: 'topology',
            scanSource: scanSource ?? null,
            zIndex: 0,
          });
        }
      }
    }

    // Layout — scan sources at center, hosts fill disk via sunflower model
    const nodeCount = g.order;
    const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5)); // ~137.5°
    // Collect scan sources and space them around center
    const sourceNodes: string[] = [];
    g.forEachNode((node, attrs) => {
      if (attrs.isScanSource || attrs.nodeType === 'scan_source') sourceNodes.push(node);
    });

    // Tiny graphs (single scan source + a handful of hosts) get a fixed
    // deterministic ring layout, no ForceAtlas2. The sunflower formula
    // puts the i=0 node at radius 0, which collides with the centered
    // scan source; FA2 with 2 overlapping points produces near-zero
    // separation because gravity (pull-to-center) overpowers the
    // repulsion when there's almost nothing to push against. The
    // user-visible symptom is two nodes glued together with Sigma's
    // hit-test picking whichever the z-index put on top — drags feel
    // "stuck" because the wrong node is being grabbed.
    const isTiny = nodeCount <= 5;
    if (isTiny) {
      const nonSourceNodes: string[] = [];
      g.forEachNode((node, attrs) => {
        if (!(attrs.isScanSource || attrs.nodeType === 'scan_source')) {
          nonSourceNodes.push(node);
        }
      });
      // Single source: dead center. Multiple sources: small inner ring.
      sourceNodes.forEach((node, idx) => {
        const angle = sourceNodes.length > 1 ? (idx / sourceNodes.length) * 2 * Math.PI : 0;
        const offset = sourceNodes.length > 1 ? 0.15 : 0;
        g.setNodeAttribute(node, 'x', offset * Math.cos(angle));
        g.setNodeAttribute(node, 'y', offset * Math.sin(angle));
      });
      // Hosts on a unit ring around the source(s). Spacing is regular,
      // so two hosts land opposite each other, three form a triangle,
      // etc. — predictable, never overlapping.
      nonSourceNodes.forEach((node, idx) => {
        const angle = (idx / nonSourceNodes.length) * 2 * Math.PI;
        g.setNodeAttribute(node, 'x', Math.cos(angle));
        g.setNodeAttribute(node, 'y', Math.sin(angle));
      });
    } else {
      let i = 0;
      g.forEachNode((node, attrs) => {
        if (attrs.isScanSource || attrs.nodeType === 'scan_source') {
          // Multiple scan sources: spread around center; single: dead center
          const srcIdx = sourceNodes.indexOf(node);
          const angle = sourceNodes.length > 1 ? (srcIdx / sourceNodes.length) * 2 * Math.PI : 0;
          const offset = sourceNodes.length > 1 ? 0.15 : 0;
          g.setNodeAttribute(node, 'x', offset * Math.cos(angle));
          g.setNodeAttribute(node, 'y', offset * Math.sin(angle));
        } else {
          // Vogel's model: r = sqrt(i/N), θ = i * golden_angle
          const r = Math.sqrt(i / nodeCount);
          const theta = i * GOLDEN_ANGLE;
          g.setNodeAttribute(node, 'x', r * Math.cos(theta));
          g.setNodeAttribute(node, 'y', r * Math.sin(theta));
          i++;
        }
      });

      // ForceAtlas2 settings scale with network size
      const isLarge = nodeCount > 200;
      const isHuge = nodeCount > 800;
      const gravity = isHuge ? 0.5 : isLarge ? 1 : 3;
      const scalingRatio = isHuge ? 100 : isLarge ? 30 : 8;
      const iterations = isHuge ? 500 : isLarge ? 350 : Math.min(300, 80 + nodeCount * 2);

      forceAtlas2.assign(g, {
        iterations,
        settings: {
          gravity,
          scalingRatio,
          barnesHutOptimize: nodeCount > 50,
          barnesHutTheta: isHuge ? 0.8 : 0.5,
          strongGravityMode: false,
          slowDown: isLarge ? 8 : 5,
          outboundAttractionDistribution: true,
        },
      });

      // Post-layout: redistribute radii to fill disk uniformly
      // FA2 groups nodes angularly, but puts them all at same radius (ring).
      // Fix: preserve angle, remap radius so nodes fill center→edge evenly.
      if (isLarge) {
        // Find center of mass (scan source position)
        let cx = 0, cy = 0, sourceCount = 0;
        g.forEachNode((_node, attrs) => {
          if (attrs.isScanSource || attrs.nodeType === 'scan_source') {
            cx += attrs.x as number;
            cy += attrs.y as number;
            sourceCount++;
          }
        });
        if (sourceCount > 0) { cx /= sourceCount; cy /= sourceCount; }

        // Collect non-source nodes with their angle and current radius
        const nodes: { id: string; angle: number; radius: number }[] = [];
        g.forEachNode((node, attrs) => {
          if (attrs.isScanSource || attrs.nodeType === 'scan_source') return;
          const dx = (attrs.x as number) - cx;
          const dy = (attrs.y as number) - cy;
          const radius = Math.sqrt(dx * dx + dy * dy);
          const angle = Math.atan2(dy, dx);
          nodes.push({ id: node, angle, radius });
        });

        // Sort by radius, then assign new radii to fill disk with a minimum distance from center
        nodes.sort((a, b) => a.radius - b.radius);
        const maxR = nodes.length > 0 ? nodes[nodes.length - 1].radius : 1;
        const minRatio = 0.25; // inner 25% of radius is empty (keeps center clear)
        for (let j = 0; j < nodes.length; j++) {
          const t = Math.sqrt((j + 1) / nodes.length); // 0..1 uniform disk fill
          const newR = maxR * (minRatio + (1 - minRatio) * t); // remap to [25%..100%] of radius
          const { id, angle } = nodes[j];
          g.setNodeAttribute(id, 'x', cx + newR * Math.cos(angle));
          g.setNodeAttribute(id, 'y', cy + newR * Math.sin(angle));
        }
      }
    }

    return g;
  }, [data, attackEdgeMap, scanSourceColorMap]);

  // Sigma instance management
  useEffect(() => {
    if (!containerRef.current || !graph) return;

    if (sigmaRef.current) {
      sigmaRef.current.kill();
      sigmaRef.current = null;
    }

    const sigma = new Sigma(graph, containerRef.current, {
      renderEdgeLabels: false,
      labelColor: { color: '#e5e7eb' },
      labelSize: 12,
      labelRenderedSizeThreshold: 6,
      defaultEdgeType: 'arrow',
      stagePadding: 40,
      zIndex: true,
      // Sigma's default hover draws a white pill behind node+label, which
      // clashes with the dark canvas and hides the gray label text. Same
      // geometry, dark fill — pill reads as a subtle highlight instead of
      // a glare. Mirrors the default in sigma/src/rendering/node-hover.ts.
      defaultDrawNodeHover: (context, data, settings) => {
        const size = settings.labelSize;
        const font = settings.labelFont;
        const weight = settings.labelWeight;
        context.font = `${weight} ${size}px ${font}`;

        context.fillStyle = 'rgb(86, 86, 86)';
        context.shadowOffsetX = 0;
        context.shadowOffsetY = 0;
        context.shadowBlur = 8;
        context.shadowColor = '#000';

        const PADDING = 2;
        if (typeof data.label === 'string') {
          const textWidth = context.measureText(data.label).width;
          const boxWidth = Math.round(textWidth + 5);
          const boxHeight = Math.round(size + 2 * PADDING);
          const radius = Math.max(data.size, size / 2) + PADDING;
          const angleRadian = Math.asin(boxHeight / 2 / radius);
          const xDeltaCoord = Math.sqrt(
            Math.abs(radius * radius - (boxHeight / 2) * (boxHeight / 2)),
          );
          context.beginPath();
          context.moveTo(data.x + xDeltaCoord, data.y + boxHeight / 2);
          context.lineTo(data.x + radius + boxWidth, data.y + boxHeight / 2);
          context.lineTo(data.x + radius + boxWidth, data.y - boxHeight / 2);
          context.lineTo(data.x + xDeltaCoord, data.y - boxHeight / 2);
          context.arc(data.x, data.y, radius, angleRadian, -angleRadian);
          context.closePath();
          context.fill();
        } else {
          context.beginPath();
          context.arc(data.x, data.y, data.size + PADDING, 0, Math.PI * 2);
          context.closePath();
          context.fill();
        }

        context.shadowBlur = 0;

        if (data.label) {
          context.fillStyle = '#e5e7eb'; // gray-200 — same as labelColor
          context.fillText(data.label, data.x + data.size + 3, data.y + size / 3);
        }
      },
    });

    sigma.on('clickNode', ({ node }) => {
      const attrs = graph.getNodeAttributes(node);
      if (attrs.nodeType === 'host' && attrs.ip) {
        onSelectHost(attrs.ip as string);
        return;
      }
      // Standalone scan-source nodes (operator boxes that never got
      // scanned themselves) open the ScanSourceDetail panel instead
      // of the host one. The node id is "source:<name>", we strip
      // the prefix to get the name the API expects.
      if (attrs.nodeType === 'scan_source' && onSelectScanSource) {
        const name = node.startsWith('source:') ? node.slice('source:'.length) : (attrs.ip as string);
        if (name) onSelectScanSource(name);
      }
    });

    sigma.on('clickStage', () => {
      onSelectHost(null);
      setContextMenu(null);
      onClearPath?.();
    });

    sigma.on('enterNode', ({ node, event }) => {
      setHoveredNode(node);
      setTooltipPos({ x: event.x, y: event.y });
    });

    sigma.on('leaveNode', () => {
      setHoveredNode(null);
    });

    // --- Right-click context menu (owned/target) ---
    sigma.on('rightClickNode', ({ node, event }) => {
      event.original.preventDefault();
      const attrs = graph.getNodeAttributes(node);
      if (attrs.nodeType !== 'host' || !attrs.ip) return;
      const ip = attrs.ip as string;
      const info = hostVulnMapRef.current.get(ip);
      // Only mouse events carry clientX/clientY
      const orig = event.original as MouseEvent;
      setContextMenu({
        x: orig.clientX ?? 0,
        y: orig.clientY ?? 0,
        ip,
        owned: info?.owned ?? false,
        target: info?.target ?? false,
      });
    });

    // Right-click on empty canvas = close the host detail pane.
    // Mirrors the pentester "cancel / back out" habit from tools like
    // Burp / BloodHound. Left-click stage is deliberately NOT wired here
    // so an accidental click on the graph while studying a host can't
    // wipe the workspace — right-click is deliberate, left-click isn't.
    sigma.on('rightClickStage', ({ event }) => {
      event.original.preventDefault();
      onCloseDetail?.();
    });

    // --- Node drag-and-drop ---
    //
    // Two subtleties make a naive drag handler look broken in tiny graphs:
    //
    // 1. Sigma's mouseCaptor pans the camera on mousemove unless we call
    //    ``preventSigmaDefault()`` on the ``mousemovebody`` event. The DOM
    //    mousemove listeners we used before never reached that flag, so
    //    the camera kept panning underneath our node update.
    //
    // 2. Sigma rebuilds its ``normalizationFunction`` every render from the
    //    current ``nodeExtent`` (the bounding box of all node coordinates).
    //    With two nodes, dragging one stretches the extent, and the new
    //    normalization re-centers the box -- so the *other* node visibly
    //    slides in the opposite direction even though its graph attrs
    //    never changed. The visible symptom is the "two points orbit
    //    around their midpoint" effect on tiny graphs.
    //    Fix: call ``setCustomBBox(getBBox())`` on mousedown to lock the
    //    bounding box at its pre-drag extent. Sigma then keeps every
    //    non-dragged node fixed in viewport for the duration of the drag.
    let draggedNode: string | null = null;
    let isDragging = false;
    const mouseCaptor = sigma.getMouseCaptor();

    sigma.on('downNode', ({ node, event }) => {
      // Only the LEFT mouse button starts a drag. Right-click is reserved
      // for the host context menu (set-as-target / mark-as-owned) — if
      // we accepted the right-button mousedown here too, every
      // right-click would attach the node to the cursor until the
      // contextmenu released; the menu would still appear, but the
      // node "stuck" to the pointer mid-flight. Filter at button level.
      const original = event.original as MouseEvent;
      if (original.button !== 0) return;
      draggedNode = node;
      isDragging = false;
      // Lock the bounding box so other nodes don't drift as this one moves.
      // Once set, we keep the lock for the entire session: releasing on
      // mouseup would force Sigma to recompute ``nodeExtent`` from the
      // new post-drag positions, and the normalization shift produces
      // a "teleport" effect where the static nodes hop slightly the
      // moment the drag ends. With the lock held, every non-dragged
      // node stays exactly where the user last placed it.
      if (!sigma.getCustomBBox()) sigma.setCustomBBox(sigma.getBBox());
      original.preventDefault();
      original.stopPropagation();
    });

    const onMouseMoveBody = (e: { x: number; y: number; preventSigmaDefault: () => void; original: MouseEvent }) => {
      if (!draggedNode) return;
      isDragging = true;
      const pos = sigma.viewportToGraph({ x: e.x, y: e.y });
      graph.setNodeAttribute(draggedNode, 'x', pos.x);
      graph.setNodeAttribute(draggedNode, 'y', pos.y);
      // Stop Sigma's camera from also panning on the same mousemove
      e.preventSigmaDefault();
      e.original.preventDefault();
      e.original.stopPropagation();
    };

    const onMouseUp = () => {
      draggedNode = null;
      isDragging = false;
      // BBox lock is deliberately NOT released here — see downNode comment.
    };

    mouseCaptor.on('mousemovebody', onMouseMoveBody);
    mouseCaptor.on('mouseup', onMouseUp);

    const container = containerRef.current;
    const handleContextMenu = (e: MouseEvent) => e.preventDefault();
    container.addEventListener('contextmenu', handleContextMenu);

    sigmaRef.current = sigma;

    return () => {
      mouseCaptor.off('mousemovebody', onMouseMoveBody);
      mouseCaptor.off('mouseup', onMouseUp);
      container.removeEventListener('contextmenu', handleContextMenu);
      sigma.kill();
      sigmaRef.current = null;
    };
  }, [graph, onSelectHost, onSelectScanSource, onClearPath, onCloseDetail]);

  // Collect nodes that participate in attack paths, expanded along the
  // topology chain. ``attackOnly`` mode dims nodes outside this set, so
  // intermediate hops (gw, dmz-switch) need to be included — otherwise
  // they'd vanish from the canvas the moment the operator flips the
  // Attack Paths toggle, breaking the chain.
  const attackNodeIds = useMemo(() => {
    const ids = new Set<string>();
    if (!pathsData) return ids;
    for (const path of pathsData.paths) {
      // Endpoint nodes (hosts and the scan source) are always included.
      for (const node of path.nodes) {
        ids.add(`host:${node.ip}`);
        ids.add(`source:${node.ip}`);
      }
      // Topology hops between consecutive nodes in the path.
      for (let i = 0; i < path.nodes.length - 1; i++) {
        const startId = resolveNodeId(path.nodes[i].ip);
        const endId = resolveNodeId(path.nodes[i + 1].ip);
        if (!startId || !endId) continue;
        for (const ekey of findTopologyPath(startId, endId)) {
          const [s, t] = ekey.split('->');
          ids.add(s);
          ids.add(t);
        }
      }
    }
    return ids;
  }, [pathsData, resolveNodeId, findTopologyPath]);

  // Highlight-path node set, expanded along the topology chain so the
  // intermediate hops between consecutive path-nodes also stay visible
  // when the operator clicks a specific attack path in the side panel.
  // Without this expansion the gateway and DMZ-switch hops would be
  // dimmed by the nodeReducer and the chain would visually break.
  const expandedPathNodeIds = useMemo(() => {
    if (!highlightPathIps) return null;
    const ids = new Set<string>();
    for (const ip of highlightPathIps) {
      ids.add(`host:${ip}`);
      ids.add(`source:${ip}`);
    }
    for (let i = 0; i < highlightPathIps.length - 1; i++) {
      const startId = resolveNodeId(highlightPathIps[i]);
      const endId = resolveNodeId(highlightPathIps[i + 1]);
      if (!startId || !endId) continue;
      for (const ekey of findTopologyPath(startId, endId)) {
        const [s, t] = ekey.split('->');
        ids.add(s);
        ids.add(t);
      }
    }
    return ids;
  }, [highlightPathIps, resolveNodeId, findTopologyPath]);

  // Set of hidden node IDs based on filters
  const hiddenNodes = useMemo(() => {
    if (!graph) return new Set<string>();
    const hidden = new Set<string>();
    const hasRoleFilter = filterRoles.size > 0;

    graph.forEachNode((node, attrs) => {
      if (attrs.nodeType !== 'host') return;
      const role = (attrs.role as string || '').toUpperCase();
      const ip = attrs.ip as string;
      const info = hostVulnMap.get(ip);

      if (filterVulnOnly && (!info || info.vulnCount === 0)) {
        hidden.add(node);
      }
      if (hasRoleFilter && !filterRoles.has(role)) {
        hidden.add(node);
      }
    });
    return hidden;
  }, [graph, filterVulnOnly, filterRoles, hostVulnMap]);

  // Highlight selected host + attack-only filter + graph filters
  useEffect(() => {
    if (!sigmaRef.current || !graph) return;

    const sigma = sigmaRef.current;
    const selectedNodeId = selectedHost ? `host:${selectedHost}` : null;

    sigma.setSetting('nodeReducer', (node, attrs) => {
      // Graph filters: dim hidden nodes
      if (hiddenNodes.has(node)) {
        return { ...attrs, color: attrs.color + '08', label: '', size: 1.5, zIndex: -1 };
      }

      // Apply hostVulnMap data: vuln-based sizing, diff labels
      const ip = attrs.ip as string;
      const info = hostVulnMapRef.current.get(ip);
      let size = attrs.size as number;
      let label = attrs.label as string;
      let forceLabel = false;

      if (info) {
        if (info.vulnCount > 0) {
          if (info.hasExploit) {
            // Has public exploit — largest: 14 base + increment
            size = Math.max(size, 14 + info.vulnCount * 0.4);
          } else if (info.maxCvss >= 7.0) {
            // High CVSS — medium: 10 base + increment
            size = Math.max(size, 10 + info.vulnCount * 0.4);
          } else {
            // Low/medium CVSS — small bump
            size = Math.max(size, 8 + info.vulnCount * 0.3);
          }
          size = Math.min(size, 22);
        }
        // Scan-diff prefixes + ownership markers. Colour emoji render
        // via the browser font stack in Sigma's label pipeline, so they
        // stand out naturally against the dark canvas. Shape is the
        // primary signal (skull vs bullseye vs sparkles vs arrows vs X)
        // so colorblind viewers can still tell them apart without
        // relying on hue.
        if (info.isStale) {
          label = `❌ ${label}`;
          forceLabel = true;
        } else if (info.isNew) {
          label = `⭐ ${label}`;
          forceLabel = true;
        } else if (info.hasChanges) {
          // `\uFE0F` is the VS16 emoji variation selector — forces the
          // warning sign to render as the yellow emoji glyph instead of
          // a monochrome text symbol across every OS font stack.
          label = `⚠\uFE0F ${label}`;
          forceLabel = true;
        }

        if (info.owned) {
          // 💀 matches the Skull icon on the "Mark as Owned" context
          // menu and carries the pentester "pwned" semantic.
          label = `💀 ${label}`;
          forceLabel = true;
        }
        if (info.target) {
          label = `🎯 ${label}`;
          forceLabel = true;
          // Mild size boost so targets remain spottable on a crowded
          // graph without changing the role colour (role colour = DC
          // red would collide with a "target red" override).
          size = Math.min(size * 1.35, 28);
        }
      }

      // Standalone scan-source nodes (operator's external box, the
      // one that never got scanned itself). They're not in
      // hostVulnMap because they're not :Host nodes, but they ARE
      // owned by definition — to run nmap from a box, the pentester
      // controls it. Same 💀 marker as for compromised hosts; the
      // red colour baked in at graph-build time is what tells them
      // apart visually from a real owned DC.
      if (attrs.nodeType === 'scan_source') {
        label = `💀 ${label}`;
        forceLabel = true;
      }

      // Color: keep the role color (or scan-source red, or
      // incomplete-host gray) baked in at graph-build time. Owned
      // status is signalled by the 💀 label prefix, not by recoloring.
      // Earlier iterations overrode owned hosts to green, which
      // erased the role information ("is this owned DC or owned DB?")
      // and conflicted with the new convention where standalone scan
      // sources are red. The marker does the job; colours stay
      // semantically stable.
      const base = { ...attrs, size, label, forceLabel };

      // Path highlight mode: dim everything except selected path.
      // ``expandedPathNodeIds`` includes the intermediate topology
      // hops so the chain stays visible through gw / dmz-switch.
      if (expandedPathNodeIds) {
        if (expandedPathNodeIds.has(node)) {
          return { ...base, size: base.size * 1.5, forceLabel: true, zIndex: 10 };
        }
        return { ...base, color: base.color + '15', label: '', size: 2, zIndex: -1 };
      }

      // Attack-only mode: dim nodes not in any attack path
      if (attackOnly && !attackNodeIds.has(node)) {
        if (selectedNodeId && node === selectedNodeId) {
          return { ...base, size: base.size * 1.8, zIndex: 2 };
        }
        return { ...base, color: base.color + '15', label: '', size: 2 };
      }

      if (selectedNodeId) {
        if (node === selectedNodeId) {
          return { ...base, size: base.size * 1.8, zIndex: 2 };
        }
        return { ...base, color: base.color + '55', label: '' };
      }
      return base;
    });

    sigma.setSetting('edgeReducer', (edge, attrs) => {
      const src = graph.source(edge);
      const tgt = graph.target(edge);
      const isAttack = attackEdgeMap.has(`${src}->${tgt}`);

      // Hide edges connected to filtered-out nodes
      if (hiddenNodes.has(src) || hiddenNodes.has(tgt)) {
        return { ...attrs, hidden: true };
      }

      // Path highlight mode (chain-aware via expandedPathNodeIds)
      if (expandedPathNodeIds) {
        if (expandedPathNodeIds.has(src) && expandedPathNodeIds.has(tgt)) {
          return { ...attrs, color: '#ef4444', size: 2.5, zIndex: 10 };
        }
        return { ...attrs, hidden: true };
      }

      // Attack-only mode: hide edges that are NOT on any attack chain.
      // Topology edges that ARE on a chain (red-tinted below) stay
      // visible — they're the actual visualization of the attack path.
      if (attackOnly && !isAttack) {
        return { ...attrs, hidden: true };
      }

      // Default view keeps the scan-source colour and size the edge was
      // built with — no attack-chain colour or thickness override. On a
      // real engagement 80%+ of hosts carry at least one vulnerability,
      // so a constant attack overlay drowns out the scan-source palette
      // and turns the canvas into noise. The red visual is reserved for
      // two user-initiated focus modes above this branch:
      //   - ``expandedPathNodeIds`` (operator clicked a specific attack
      //     path in the side panel — that path renders red)
      //   - Attack-paths-only toggle filters non-attack edges out, but
      //     the survivors keep their scan-source colour (the toggle
      //     answers "show me only what's on an attack path" via
      //     visibility, not via colour).
      if (selectedNodeId) {
        if (src === selectedNodeId || tgt === selectedNodeId) {
          return { ...attrs, size: (attrs.size as number) * 1.5 };
        }
        return { ...attrs, hidden: true };
      }
      return attrs;
    });

    sigma.refresh();
  }, [
    selectedHost, graph, attackOnly, attackNodeIds, hiddenNodes,
    highlightPathIps, attackEdgeMap, expandedPathNodeIds,
  ]);

  // Tooltip data
  const tooltipData = useMemo(() => {
    if (!hoveredNode || !graph || !graph.hasNode(hoveredNode)) return null;
    const attrs = graph.getNodeAttributes(hoveredNode);
    if (attrs.nodeType !== 'host' && attrs.nodeType !== 'scan_source') return null;
    const ip = attrs.ip as string;
    const info = hostVulnMap.get(ip);
    return {
      ip,
      role: attrs.role as string,
      vulnCount: info?.vulnCount || 0,
      maxCvss: info?.maxCvss ?? -1,
      hasExploit: info?.hasExploit || false,
      isScanSource: (attrs.isScanSource as boolean) || attrs.nodeType === 'scan_source',
      isIncomplete: (attrs.isIncomplete as boolean) || false,
      isNew: info?.isNew || false,
      isStale: info?.isStale || false,
      topVulns: info?.topVulns || [],
    };
  }, [hoveredNode, graph, hostVulnMap]);

  const renderTooltip = useCallback(() => {
    if (!tooltipData) return null;
    const { ip, role, vulnCount, maxCvss, hasExploit, isScanSource, isIncomplete, isNew, isStale, topVulns } = tooltipData;
    return (
      <div
        ref={tooltipRef}
        className="absolute z-50 pointer-events-none rounded bg-gray-900 border border-gray-700 px-3 py-2 shadow-xl max-w-xs"
        style={{ left: tooltipPos.x + 12, top: tooltipPos.y - 10 }}
      >
        <div className="flex items-center gap-1.5 flex-wrap">
          <p className="text-xs font-mono text-gray-100 font-semibold">{ip}</p>
          {isNew && <Badge tone="green">NEW</Badge>}
          {isStale && <Badge tone="gray">GONE</Badge>}
          {isScanSource && <Badge tone="green">PIVOT</Badge>}
          {isIncomplete && <Badge tone="gray">NO PORTS</Badge>}
        </div>
        <p className="text-xs text-gray-400 mt-0.5">{role}</p>
        {isIncomplete && (
          <p className="text-xs text-gray-500 mt-1 italic">
            No services yet — rescan from a closer position or with different flags.
          </p>
        )}
        {vulnCount > 0 ? (
          <div className="mt-1.5 space-y-0.5">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-semibold text-gray-300">
                {vulnCount} vuln{vulnCount !== 1 ? 's' : ''}
              </span>
              <span className="text-xs font-mono" style={{ color: maxCvss > 0 ? getCvssColor(maxCvss) : '#6b7280' }}>
                CVSS: {formatCvss(maxCvss)}
              </span>
              {hasExploit && <Badge tone="red">EXPLOIT</Badge>}
            </div>
            {topVulns.map((v) => (
              <div key={v.cve_id} className="flex items-center gap-1.5 text-xs">
                {v.port != null && (
                  <span className="font-mono text-gray-500 w-10 text-right shrink-0">:{v.port}</span>
                )}
                <span className="text-gray-300 truncate">{v.cve_id}</span>
                <span style={{ color: getConfidenceColor(v.confidence) }} className="shrink-0">
                  {v.confidence}
                </span>
                {v.cvss > 0 && (
                  <span className="font-mono shrink-0" style={{ color: getCvssColor(v.cvss) }}>
                    {v.cvss.toFixed(1)}
                  </span>
                )}
                {v.checked_status === 'exploited' && (
                  <Check size={11} className="text-green-400 shrink-0" />
                )}
                {v.checked_status === 'false_positive' && (
                  <XIcon size={11} className="text-gray-500 shrink-0" />
                )}
                {v.checked_status === 'mitigated' && (
                  <Shield size={11} className="text-blue-400 shrink-0" />
                )}
                {v.has_exploit && (
                  <span className="text-red-400 font-semibold shrink-0 text-xs">EXP</span>
                )}
              </div>
            ))}
            {vulnCount > topVulns.length && (
              <p className="text-xs text-gray-600">+{vulnCount - topVulns.length} more</p>
            )}
          </div>
        ) : (
          <p className="text-xs text-gray-600 mt-1">No vulnerabilities</p>
        )}
      </div>
    );
  }, [tooltipData, tooltipPos]);

  // Splash screen only on the very first load. Background refetches
  // (after a context-menu Owned/Target toggle or refreshKey bump)
  // keep the rendered graph in place so the operator's pan/zoom and
  // node-selection state survive the round-trip.
  if (loading && !data) {
    return (
      <div className="flex h-full items-center justify-center bg-gray-950">
        <div className="flex flex-col items-center gap-3 text-center">
          {/* Cauldron mid-brew as the loading indicator. On a large
              dataset the graph can take 5-15 seconds to fetch and
              layout — a bubbling cauldron reads as "the pipeline is
              actively working", which is what's happening, instead of
              the neutral "please wait" of a spinner.
              Use the 84×100 splash sprite (animated, 12 frames) — the
              smaller anim-32 source turned mushy when scaled to 144. */}
          <img
            src="/brand/cauldron-splash.webp"
            alt=""
            width={144}
            height={144}
            style={{
              imageRendering: 'pixelated',
              filter: 'drop-shadow(0 6px 16px rgba(0,0,0,0.5))',
            }}
          />
          <p className="text-sm text-gray-400">Brewing the graph…</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex h-full items-center justify-center bg-gray-950">
        <div className="text-center">
          <p className="mb-2 text-sm text-red-400">Failed to load graph</p>
          <p className="mb-3 text-xs text-gray-500">{error}</p>
          <button
            onClick={refetch}
            className="rounded bg-steel-600 px-3 py-1.5 text-xs text-white hover:bg-steel-500"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!data || data.nodes.length === 0) {
    return (
      <div className="flex h-full items-center justify-center bg-gray-950">
        <div className="flex flex-col items-center gap-4 text-center">
          {/* Hero cauldron — empty canvas, nothing to distract from it.
              Drop-shadow grounds the sprite on the dark background and
              gives the pixel silhouette a touch of depth without breaking
              the pixel-art aesthetic. */}
          <img
            src="/brand/cauldron-splash.webp"
            alt="Cauldron"
            width={144}
            height={144}
            className="select-none"
            style={{
              imageRendering: 'pixelated',
              filter: 'drop-shadow(0 10px 24px rgba(0,0,0,0.5))',
            }}
          />
          <div>
            <p className="text-base font-semibold text-gray-200">An empty cauldron</p>
            <p className="mt-1 text-xs text-gray-500">Drop a scan on the Import tab and start brewing.</p>
          </div>
        </div>
      </div>
    );
  }

  // Rendered host count (data.nodes includes segments + scan-sources, strip
  // to just the host type to compare against total_hosts).
  const renderedHostCount = data.nodes.filter((n) => n.type === 'host').length;
  const truncated = data.total_hosts > 0 && renderedHostCount < data.total_hosts;

  return (
    <div className="relative w-full h-full">
      <div ref={containerRef} className="sigma-container" />
      {/* Truncation banner — only visible when graph was capped. Uses amber
          accent (matches the DB/brute-vuln family) so it reads as a warning
          without screaming red. */}
      {truncated && (
        <div
          className="absolute top-3 left-3 max-w-sm rounded-lg border border-amber-700/50 bg-amber-950/70 px-3 py-1.5 text-xs text-amber-200 backdrop-blur"
          title={`Showing the top ${renderedHostCount} hosts (by vuln count, then role). ${data.total_hosts - renderedHostCount} hosts hidden — the tail is typically 'unknown' role with no CVEs.`}
        >
          Showing <span className="font-semibold">{renderedHostCount}</span> of{' '}
          <span className="font-semibold">{data.total_hosts}</span> hosts
          <span className="ml-1 text-amber-400/70">(untriaged tail hidden)</span>
        </div>
      )}
      {/* Controls bar */}
      <div className="absolute top-3 right-3 flex items-center gap-2">

      {/* Legend — hover chip. Lives on the graph canvas because that
          is the only view where role colours and state glyphs apply. */}
      <Legend scanSources={scanSourcesData ?? []} />

      {/* Filter button */}
      <div
        className="relative"
        onMouseEnter={showFiltersPanel}
        onMouseLeave={scheduleHideFilters}
        onFocus={showFiltersPanel}
        onBlur={scheduleHideFilters}
      >
        <button
          type="button"
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs border transition-colors ${
            (filterVulnOnly || filterRoles.size > 0)
              ? 'bg-steel-900/90 border-steel-600 text-steel-300'
              : 'bg-gray-900/90 border-gray-700 text-gray-400 hover:text-gray-200'
          }`}
        >
          <SlidersHorizontal size={13} />
          Filters
          {(filterVulnOnly || filterRoles.size > 0) && (
            <span className="rounded-full bg-steel-500 text-white px-1.5 py-0 text-xs leading-4">
              {(filterVulnOnly ? 1 : 0) + filterRoles.size}
            </span>
          )}
        </button>

        {showFilters && (
          <div className="absolute right-0 top-full mt-1 w-56 rounded-lg bg-gray-900 border border-gray-700 p-2 shadow-xl z-50">
            {/* Vuln-only toggle */}
            <label className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-gray-800 cursor-pointer">
              <input
                type="checkbox"
                checked={filterVulnOnly}
                onChange={(e) => setFilterVulnOnly(e.target.checked)}
                className="rounded border-gray-600 bg-gray-800 text-steel-500"
              />
              <span className="text-xs text-gray-300">Vulnerable hosts only</span>
            </label>

            <div className="border-t border-gray-700 my-1" />
            <p className="px-2 py-1 text-xs text-gray-500 font-medium">Filter by role</p>

            {/* Role checkboxes */}
            <div className="max-h-48 overflow-y-auto space-y-0.5">
              {Object.entries(ROLE_COLORS).filter(([k]) => k !== 'unknown').map(([role, color]) => (
                <label key={role} className="flex items-center gap-2 px-2 py-0.5 rounded hover:bg-gray-800 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={filterRoles.has(role)}
                    onChange={(e) => {
                      const next = new Set(filterRoles);
                      if (e.target.checked) next.add(role);
                      else next.delete(role);
                      setFilterRoles(next);
                    }}
                    className="rounded border-gray-600 bg-gray-800 text-steel-500"
                  />
                  <div className="h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: color }} />
                  <span className="text-xs text-gray-400">{role.toLowerCase().replace(/_/g, ' ')}</span>
                </label>
              ))}
            </div>

            {/* Clear filters */}
            {(filterVulnOnly || filterRoles.size > 0) && (
              <>
                <div className="border-t border-gray-700 my-1" />
                <button
                  onClick={() => { setFilterVulnOnly(false); setFilterRoles(new Set()); }}
                  className="w-full rounded px-2 py-1 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-200"
                >
                  Clear all filters
                </button>
              </>
            )}
          </div>
        )}
      </div>

      {/* View toggle */}
      <div className="flex rounded-lg bg-gray-900/90 border border-gray-700 overflow-hidden">
        <button
          onClick={() => setAttackOnly(false)}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
            !attackOnly ? 'bg-steel-600 text-white' : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <Network size={13} />
          All
        </button>
        <button
          onClick={() => setAttackOnly(true)}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${
            attackOnly ? 'bg-red-600 text-white' : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <Crosshair size={13} />
          Attack Paths
        </button>
      </div>

      </div>
      {renderTooltip()}

      {/* Right-click context menu for owned/target */}
      {contextMenu && (
        <>
          {/* Click-outside overlay */}
          <div
            className="fixed inset-0 z-[998]"
            onClick={() => setContextMenu(null)}
            onContextMenu={(e) => { e.preventDefault(); setContextMenu(null); }}
          />
        <div
          className="fixed z-[999] rounded-lg bg-gray-900 border border-gray-700 shadow-xl py-1 min-w-[160px]"
          style={{ left: contextMenu.x, top: contextMenu.y }}
        >
          <div className="px-3 py-1 text-xs text-gray-500 font-mono border-b border-gray-800">
            {contextMenu.ip}
          </div>
          <button
            className="w-full text-left px-3 py-1.5 text-xs hover:bg-gray-800 flex items-center gap-2"
            onClick={async () => {
              await api.setHostOwned(contextMenu.ip, !contextMenu.owned);
              setContextMenu(null);
              refetchHosts();
              onDataChanged?.();
            }}
          >
            <Skull
              size={13}
              className={`${contextMenu.owned ? 'text-green-400' : 'text-gray-500'} shrink-0`}
            />
            <span className={contextMenu.owned ? 'text-green-400' : 'text-gray-400'}>
              {contextMenu.owned ? 'Unmark Owned' : 'Mark as Owned'}
            </span>
          </button>
          <button
            className="w-full text-left px-3 py-1.5 text-xs hover:bg-gray-800 flex items-center gap-2"
            onClick={async () => {
              await api.setHostTarget(contextMenu.ip, !contextMenu.target);
              setContextMenu(null);
              refetchHosts();
              onDataChanged?.();
            }}
          >
            <Target
              size={13}
              className={`${contextMenu.target ? 'text-red-400' : 'text-gray-500'} shrink-0`}
            />
            <span className={contextMenu.target ? 'text-red-400' : 'text-gray-400'}>
              {contextMenu.target ? 'Remove Target' : 'Set as Target'}
            </span>
          </button>
        </div>
        </>
      )}
    </div>
  );
}
