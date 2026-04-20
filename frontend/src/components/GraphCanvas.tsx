import { useEffect, useRef, useMemo, useState, useCallback } from 'react';
import { MultiGraph } from 'graphology';
import Sigma from 'sigma';
import { Crosshair, Network, SlidersHorizontal } from 'lucide-react';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import { getNodeColor, getCvssColor, getConfidenceColor, ROLE_COLORS } from '../utils/colors';
import { HIGH_VALUE_ROLES, formatCvss } from '../utils/format';
import type { GraphResponse, PathsResponse, HostListResponse, VulnOut } from '../types';

interface Props {
  selectedHost: string | null;
  onSelectHost: (ip: string | null) => void;
  highlightPathIps?: string[] | null;
  onClearPath?: () => void;
  onDataChanged?: () => void;
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

export function GraphCanvas({ selectedHost, onSelectHost, highlightPathIps, onClearPath, onDataChanged, refreshKey = 0 }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const sigmaRef = useRef<Sigma | null>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [attackOnly, setAttackOnly] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [filterVulnOnly, setFilterVulnOnly] = useState(false);
  const [filterRoles, setFilterRoles] = useState<Set<string>>(new Set());
  const [contextMenu, setContextMenu] = useState<{
    x: number; y: number; ip: string; owned: boolean; target: boolean;
  } | null>(null);
  const { data, loading, error, refetch } = useApi<GraphResponse>(() => api.getGraph(1000), []);
  const { data: pathsData } = useApi<PathsResponse>(
    () => api.getAttackPaths({ top: 50, include_check: true }),
    [refreshKey],
  );
  const { data: hostsData, refetch: refetchHosts } = useApi<HostListResponse>(
    () => api.getHosts({ limit: 1000 }),
    [refreshKey],
  );

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

  // Collect attack path edges with vuln count of target
  const attackEdgeMap = useMemo(() => {
    const map = new Map<string, number>(); // edgeKey -> vuln count of target
    if (!pathsData) return map;
    for (const path of pathsData.paths) {
      const target = path.nodes[path.nodes.length - 1];
      const vulnCount = target.vulns.length;
      for (let i = 0; i < path.nodes.length - 1; i++) {
        const src = `host:${path.nodes[i].ip}`;
        const tgt = `host:${path.nodes[i + 1].ip}`;
        const key = `${src}->${tgt}`;
        map.set(key, Math.max(map.get(key) || 0, vulnCount));
        const srcAlt = `source:${path.nodes[i].ip}`;
        const keyAlt = `${srcAlt}->${tgt}`;
        map.set(keyAlt, Math.max(map.get(keyAlt) || 0, vulnCount));
      }
    }
    return map;
  }, [pathsData]);

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
      const color = getNodeColor(node.type, role);

      // Base sizing: vuln-based sizing applied in nodeReducer
      let size = node.type === 'host' ? 8 : 5;
      if (isScanSource) {
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
        zIndex: isScanSource ? 100 : 1,
      });
    }

    // Topology edges: thin, dim green — skip IN_SEGMENT and CAN_REACH
    for (const edge of data.edges) {
      if (edge.type === 'IN_SEGMENT' || edge.type === 'CAN_REACH') continue;
      if (g.hasNode(edge.source) && g.hasNode(edge.target)) {
        const edgeKey = `topo:${edge.source}->${edge.target}`;
        if (!g.hasEdge(edgeKey)) {
          g.addEdgeWithKey(edgeKey, edge.source, edge.target, {
            type: 'arrow',
            size: 0.5,
            color: '#22c55e18',
            edgeType: 'topology',
            zIndex: 0,
          });
        }
      }
    }

    // Attack path edges — red, thin, arrow
    for (const [pathEdgeKey] of attackEdgeMap) {
      const [src, tgt] = pathEdgeKey.split('->');
      if (g.hasNode(src) && g.hasNode(tgt)) {
        const atkKey = `atk:${pathEdgeKey}`;
        if (!g.hasEdge(atkKey)) {
          g.addEdgeWithKey(atkKey, src, tgt, {
            type: 'arrow',
            size: 1.5,
            color: '#ef4444',
            edgeType: 'attack',
            zIndex: 10,
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

    return g;
  }, [data, attackEdgeMap]);

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
    });

    sigma.on('clickNode', ({ node }) => {
      const attrs = graph.getNodeAttributes(node);
      if (attrs.nodeType === 'host' && attrs.ip) {
        onSelectHost(attrs.ip as string);
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

    // --- Node drag-and-drop ---
    let draggedNode: string | null = null;
    let isDragging = false;

    sigma.on('downNode', ({ node, event }) => {
      draggedNode = node;
      isDragging = false;
      // Disable camera drag while dragging a node
      sigma.getCamera().disable();
      event.original.preventDefault();
      event.original.stopPropagation();
    });

    const handleMouseMove = (e: MouseEvent) => {
      if (!draggedNode) return;
      isDragging = true;
      const coords = sigma.viewportToGraph({ x: e.offsetX, y: e.offsetY });
      graph.setNodeAttribute(draggedNode, 'x', coords.x);
      graph.setNodeAttribute(draggedNode, 'y', coords.y);
    };

    const handleMouseUp = () => {
      if (draggedNode) {
        // If it was just a click (not drag), let clickNode handle it
        if (isDragging) {
          // Suppress the click after drag
          sigma.getCamera().enable();
        } else {
          sigma.getCamera().enable();
        }
        draggedNode = null;
        isDragging = false;
      }
    };

    const container = containerRef.current;
    const handleContextMenu = (e: MouseEvent) => e.preventDefault();
    container.addEventListener('mousemove', handleMouseMove);
    container.addEventListener('mouseup', handleMouseUp);
    container.addEventListener('mouseleave', handleMouseUp);
    container.addEventListener('contextmenu', handleContextMenu);

    sigmaRef.current = sigma;

    return () => {
      container.removeEventListener('mousemove', handleMouseMove);
      container.removeEventListener('mouseup', handleMouseUp);
      container.removeEventListener('mouseleave', handleMouseUp);
      container.removeEventListener('contextmenu', handleContextMenu);
      sigma.kill();
      sigmaRef.current = null;
    };
  }, [graph, onSelectHost, onClearPath]);

  // Collect nodes that participate in attack paths
  const attackNodeIds = useMemo(() => {
    const ids = new Set<string>();
    if (!pathsData) return ids;
    for (const path of pathsData.paths) {
      for (const node of path.nodes) {
        ids.add(`host:${node.ip}`);
        ids.add(`source:${node.ip}`);
      }
    }
    return ids;
  }, [pathsData]);

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

      if (info && !attrs.isScanSource) {
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
        if (info.isStale) {
          label = `× ${label}`;
          forceLabel = true;
        } else if (info.isNew) {
          label = `★ ${label}`;
          forceLabel = true;
        } else if (info.hasChanges) {
          label = `⚠ ${label}`;
          forceLabel = true;
        }

        // Owned/Target markers
        if (info.owned) {
          label = `🔓 ${label}`;
          forceLabel = true;
        }
        if (info.target) {
          label = `🎯 ${label}`;
          forceLabel = true;
        }
      }

      let nodeColor = attrs.color as string;
      // Owned hosts: green tint ring effect via brighter color
      if (info?.owned && !attrs.isScanSource) {
        nodeColor = '#22c55e';  // green — we have access
      }
      const base = { ...attrs, size, label, forceLabel, color: nodeColor };

      // Path highlight mode: dim everything except selected path
      // Node IDs can be host:{ip}, source:{name}, or host:{name} (merged pivot)
      const pathNodeIds = highlightPathIps
        ? new Set(highlightPathIps.flatMap((ip) => [`host:${ip}`, `source:${ip}`]))
        : null;

      if (pathNodeIds) {
        if (pathNodeIds.has(node)) {
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
      const edgeType = graph.getEdgeAttribute(edge, 'edgeType');
      const src = graph.source(edge);
      const tgt = graph.target(edge);

      // Hide edges connected to filtered-out nodes
      if (hiddenNodes.has(src) || hiddenNodes.has(tgt)) {
        return { ...attrs, hidden: true };
      }

      // Path highlight mode
      const pathNodeIds = highlightPathIps
        ? new Set(highlightPathIps.flatMap((ip) => [`host:${ip}`, `source:${ip}`]))
        : null;

      if (pathNodeIds) {
        if (pathNodeIds.has(src) && pathNodeIds.has(tgt)) {
          return { ...attrs, color: '#ef4444', size: 2.5, zIndex: 10 };
        }
        return { ...attrs, hidden: true };
      }

      // Attack-only mode: hide topology edges
      if (attackOnly && edgeType === 'topology') {
        return { ...attrs, hidden: true };
      }

      if (selectedNodeId) {
        if (src === selectedNodeId || tgt === selectedNodeId) {
          return { ...attrs, size: (attrs.size as number) * 1.5 };
        }
        return { ...attrs, hidden: true };
      }
      return attrs;
    });

    sigma.refresh();
  }, [selectedHost, graph, attackOnly, attackNodeIds, hiddenNodes, highlightPathIps]);

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
      isNew: info?.isNew || false,
      isStale: info?.isStale || false,
      topVulns: info?.topVulns || [],
    };
  }, [hoveredNode, graph, hostVulnMap]);

  const renderTooltip = useCallback(() => {
    if (!tooltipData) return null;
    const { ip, role, vulnCount, maxCvss, hasExploit, isScanSource, isNew, isStale, topVulns } = tooltipData;
    return (
      <div
        ref={tooltipRef}
        className="absolute z-50 pointer-events-none rounded bg-gray-900 border border-gray-700 px-3 py-2 shadow-xl max-w-xs"
        style={{ left: tooltipPos.x + 12, top: tooltipPos.y - 10 }}
      >
        <div className="flex items-center gap-2">
          <p className="text-xs font-mono text-gray-100 font-semibold">{ip}</p>
          {isNew && (
            <span className="text-xs text-green-400 font-semibold">NEW</span>
          )}
          {isStale && (
            <span className="text-xs text-gray-500 font-semibold">GONE</span>
          )}
          {isScanSource && (
            <span className="text-xs text-green-400 font-semibold">PIVOT</span>
          )}
        </div>
        <p className="text-xs text-gray-400 mt-0.5">{role}</p>
        {vulnCount > 0 ? (
          <div className="mt-1.5 space-y-0.5">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-semibold text-gray-300">
                {vulnCount} vuln{vulnCount !== 1 ? 's' : ''}
              </span>
              <span className="text-xs font-mono" style={{ color: maxCvss > 0 ? getCvssColor(maxCvss) : '#6b7280' }}>
                CVSS: {formatCvss(maxCvss)}
              </span>
              {hasExploit && (
                <span className="text-xs text-red-400 font-semibold">EXPLOIT</span>
              )}
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
                  <span className="text-green-400 shrink-0">&#10003;</span>
                )}
                {v.checked_status === 'false_positive' && (
                  <span className="text-gray-500 shrink-0">FP</span>
                )}
                {v.checked_status === 'mitigated' && (
                  <span className="text-blue-400 shrink-0">M</span>
                )}
                {v.has_exploit && (
                  <span className="text-red-400 font-semibold shrink-0">EXP</span>
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

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center bg-gray-950">
        <div className="text-center">
          <div className="mb-3 h-8 w-8 animate-spin rounded-full border-2 border-indigo-400 border-t-transparent mx-auto" />
          <p className="text-sm text-gray-400">Loading graph...</p>
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
            className="rounded bg-indigo-600 px-3 py-1.5 text-xs text-white hover:bg-indigo-500"
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
        <div className="text-center">
          <p className="text-sm text-gray-400">No graph data</p>
          <p className="mt-1 text-xs text-gray-600">Import a scan to get started</p>
        </div>
      </div>
    );
  }

  return (
    <div className="relative w-full h-full">
      <div ref={containerRef} className="sigma-container" />
      {/* Controls bar */}
      <div className="absolute top-3 right-3 flex items-center gap-2">

      {/* Filter button */}
      <div className="relative">
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs border transition-colors ${
            (filterVulnOnly || filterRoles.size > 0)
              ? 'bg-indigo-900/90 border-indigo-600 text-indigo-300'
              : 'bg-gray-900/90 border-gray-700 text-gray-400 hover:text-gray-200'
          }`}
        >
          <SlidersHorizontal size={13} />
          Filters
          {(filterVulnOnly || filterRoles.size > 0) && (
            <span className="rounded-full bg-indigo-500 text-white px-1.5 py-0 text-xs leading-4">
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
                className="rounded border-gray-600 bg-gray-800 text-indigo-500"
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
                    className="rounded border-gray-600 bg-gray-800 text-indigo-500"
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
            !attackOnly ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-gray-200'
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
            <span>{contextMenu.owned ? '🔓' : '🔒'}</span>
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
            <span>🎯</span>
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
