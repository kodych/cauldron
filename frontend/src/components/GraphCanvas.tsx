import { useEffect, useRef, useMemo, useState, useCallback } from 'react';
import { MultiGraph } from 'graphology';
import Sigma from 'sigma';
import { Crosshair, Network } from 'lucide-react';
import { circular } from 'graphology-layout';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import { getNodeColor, getCvssColor } from '../utils/colors';
import { HIGH_VALUE_ROLES, formatCvss } from '../utils/format';
import type { GraphResponse, PathsResponse, HostListResponse } from '../types';

interface Props {
  selectedHost: string | null;
  onSelectHost: (ip: string | null) => void;
}

interface HostVulnInfo {
  vulnCount: number;
  maxCvss: number;
  hasExploit: boolean;
  role: string;
}

export function GraphCanvas({ selectedHost, onSelectHost }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const sigmaRef = useRef<Sigma | null>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [attackOnly, setAttackOnly] = useState(false);

  const { data, loading, error, refetch } = useApi<GraphResponse>(() => api.getGraph(1000), []);
  const { data: pathsData } = useApi<PathsResponse>(
    () => api.getAttackPaths({ top: 50, include_check: true }),
    [],
  );
  const { data: hostsData } = useApi<HostListResponse>(
    () => api.getHosts({ limit: 1000 }),
    [],
  );

  // Build host vuln lookup from hosts data
  const hostVulnMap = useMemo(() => {
    const map = new Map<string, HostVulnInfo>();
    if (!hostsData) return map;
    for (const h of hostsData.hosts) {
      const vulns = h.vulnerabilities;
      map.set(h.ip, {
        vulnCount: vulns.length,
        maxCvss: vulns.length > 0 ? Math.max(...vulns.map((v) => v.cvss)) : -1,
        hasExploit: vulns.some((v) => v.has_exploit),
        role: h.role,
      });
    }
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
      const ip = node.properties.ip as string || '';
      const color = getNodeColor(node.type, role);
      const info = hostVulnMap.get(ip);

      // Node sizing: high-value targets are bigger, vulns add more
      let size = node.type === 'host' ? 6 : 5;
      if (node.type === 'host') {
        // High-value targets: larger base
        if (HIGH_VALUE_ROLES.has(roleUpper)) {
          size = 14;
        }
        // Vulns scale size up
        if (info && info.vulnCount > 0) {
          size = Math.max(size, 8 + info.vulnCount * 0.5);
          if (info.maxCvss >= 9.0) size = Math.max(size, 16);
          else if (info.maxCvss >= 7.0) size = Math.max(size, 12);
        }
        size = Math.min(size, 20);
      }

      g.addNode(node.id, {
        label: node.label,
        color,
        size,
        nodeType: node.type,
        role: role || '',
        ip,
        vulnCount: info?.vulnCount || 0,
        maxCvss: info?.maxCvss ?? -1,
        hasExploit: info?.hasExploit || false,
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

    // Attack path edges — red, thickness by vuln count
    for (const [pathEdgeKey, vulnCount] of attackEdgeMap) {
      const [src, tgt] = pathEdgeKey.split('->');
      if (g.hasNode(src) && g.hasNode(tgt)) {
        const atkKey = `atk:${pathEdgeKey}`;
        if (!g.hasEdge(atkKey)) {
          // Thickness: 1.5 base, logarithmic scaling, caps at 6
          const thickness = Math.min(6, 1.5 + Math.log2(1 + vulnCount) * 0.9);

          g.addEdgeWithKey(atkKey, src, tgt, {
            type: 'arrow',
            size: thickness,
            color: vulnCount >= 5 ? '#ef4444ee' :
                   vulnCount >= 3 ? '#f97316dd' :
                                    '#ef444499',
            edgeType: 'attack',
            zIndex: 10,
          });
        }
      }
    }

    // Layout
    circular.assign(g);
    forceAtlas2.assign(g, {
      iterations: 100,
      settings: {
        gravity: 1,
        scalingRatio: 10,
        barnesHutOptimize: true,
        slowDown: 5,
      },
    });

    return g;
  }, [data, attackEdgeMap, hostVulnMap]);

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
    });

    sigma.on('enterNode', ({ node, event }) => {
      setHoveredNode(node);
      setTooltipPos({ x: event.x, y: event.y });
    });

    sigma.on('leaveNode', () => {
      setHoveredNode(null);
    });

    sigmaRef.current = sigma;

    return () => {
      sigma.kill();
      sigmaRef.current = null;
    };
  }, [graph, onSelectHost]);

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

  // Highlight selected host + attack-only filter
  useEffect(() => {
    if (!sigmaRef.current || !graph) return;

    const sigma = sigmaRef.current;
    const selectedNodeId = selectedHost ? `host:${selectedHost}` : null;

    sigma.setSetting('nodeReducer', (node, attrs) => {
      // Attack-only mode: dim nodes not in any attack path
      if (attackOnly && !attackNodeIds.has(node)) {
        if (selectedNodeId && node === selectedNodeId) {
          return { ...attrs, size: attrs.size * 1.8, zIndex: 2 };
        }
        return { ...attrs, color: attrs.color + '15', label: '', size: 2 };
      }

      if (selectedNodeId) {
        if (node === selectedNodeId) {
          return { ...attrs, size: attrs.size * 1.8, zIndex: 2 };
        }
        return { ...attrs, color: attrs.color + '55', label: '' };
      }
      return attrs;
    });

    sigma.setSetting('edgeReducer', (edge, attrs) => {
      const edgeType = graph.getEdgeAttribute(edge, 'edgeType');

      // Attack-only mode: hide topology edges
      if (attackOnly && edgeType === 'topology') {
        return { ...attrs, hidden: true };
      }

      if (selectedNodeId) {
        const src = graph.source(edge);
        const tgt = graph.target(edge);
        if (src === selectedNodeId || tgt === selectedNodeId) {
          return { ...attrs, size: (attrs.size as number) * 1.5 };
        }
        return { ...attrs, hidden: true };
      }
      return attrs;
    });

    sigma.refresh();
  }, [selectedHost, graph, attackOnly, attackNodeIds]);

  // Tooltip data
  const tooltipData = useMemo(() => {
    if (!hoveredNode || !graph || !graph.hasNode(hoveredNode)) return null;
    const attrs = graph.getNodeAttributes(hoveredNode);
    if (attrs.nodeType !== 'host') return null;
    return {
      ip: attrs.ip as string,
      role: attrs.role as string,
      vulnCount: attrs.vulnCount as number,
      maxCvss: attrs.maxCvss as number,
      hasExploit: attrs.hasExploit as boolean,
    };
  }, [hoveredNode, graph]);

  const renderTooltip = useCallback(() => {
    if (!tooltipData) return null;
    const { ip, role, vulnCount, maxCvss, hasExploit } = tooltipData;
    return (
      <div
        ref={tooltipRef}
        className="absolute z-50 pointer-events-none rounded bg-gray-900 border border-gray-700 px-3 py-2 shadow-xl"
        style={{ left: tooltipPos.x + 12, top: tooltipPos.y - 10 }}
      >
        <p className="text-xs font-mono text-gray-100 font-semibold">{ip}</p>
        <p className="text-xs text-gray-400 mt-0.5">{role}</p>
        {vulnCount > 0 ? (
          <div className="mt-1 flex items-center gap-2">
            <span
              className="text-xs font-semibold"
              style={{ color: maxCvss > 0 ? getCvssColor(maxCvss) : '#6b7280' }}
            >
              {vulnCount} CVE{vulnCount !== 1 ? 's' : ''}
            </span>
            <span className="text-xs" style={{ color: maxCvss > 0 ? getCvssColor(maxCvss) : '#6b7280' }}>
              CVSS: {formatCvss(maxCvss)}
            </span>
            {hasExploit && (
              <span className="text-xs text-red-400 font-semibold">EXPLOIT</span>
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
      {/* View toggle */}
      <div className="absolute top-3 right-3 flex rounded-lg bg-gray-900/90 border border-gray-700 overflow-hidden">
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
      {renderTooltip()}
    </div>
  );
}
