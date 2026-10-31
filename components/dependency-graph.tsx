"use client";

import React, { useState, useMemo, useCallback, useEffect } from "react";
import {
  ReactFlow,
  Controls,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  Position,
  Handle,
  Node,
  Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "@dagrejs/dagre";
import {
  Package,
  ShieldAlert,
  FileCode2,
  AlertTriangle,
  CheckCircle2,
  Search,
  Filter,
  Maximize2,
  RotateCcw,
  Layers,
  ChevronRight,
  ExternalLink,
  Sparkles,
  Wrench,
  X,
  Eye,
  Info,
} from "lucide-react";
import { Report, Finding, Inspection } from "@/lib/types";
import { Eyebrow, Badge } from "./ui";

export type DependencyNodeData = {
  id: string;
  name: string;
  version: string;
  direct: boolean;
  status: string;
  reason?: string;
  location?: string;
  depth?: number | null;
  advisories: Finding[];
  behavioralFindings: Finding[];
  integrityStatus?: string;
  isRoot?: boolean;
  isSelected?: boolean;
  childCount: number;
  parentCount: number;
};

// Custom Node Component for ReactFlow
function CustomNode({ data }: { data: DependencyNodeData }) {
  const hasVuln = data.advisories.length > 0;
  const hasBehavioral = data.behavioralFindings.length > 0;
  const isSelected = data.isSelected;

  let borderClass = "";
  if (data.isRoot) {
    borderClass = "node-root";
  } else if (hasVuln && hasBehavioral) {
    borderClass = "has-both";
  } else if (hasVuln) {
    borderClass = "has-vuln";
  } else if (hasBehavioral) {
    borderClass = "has-behavioral";
  }

  return (
    <div
      className={`custom-dependency-node ${borderClass} ${isSelected ? "selected" : ""}`}
      style={{
        padding: "10px 14px",
        borderRadius: "8px",
        background: data.isRoot ? "#172554" : "#0f172a",
        border: isSelected
          ? "2px solid #818cf8"
          : data.isRoot
            ? "1px solid #3b82f6"
            : "1px solid rgba(255, 255, 255, 0.12)",
        color: "#f8fafc",
        minWidth: "170px",
        maxWidth: "230px",
        fontSize: "12px",
        boxShadow: isSelected
          ? "0 0 16px rgba(99, 102, 241, 0.5)"
          : "0 4px 10px rgba(0, 0, 0, 0.4)",
        cursor: "pointer",
        position: "relative",
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: "#6366f1", width: 7, height: 7 }}
      />

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "6px",
          marginBottom: "4px",
        }}
      >
        <span
          style={{
            fontWeight: 600,
            fontSize: "12px",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            color: data.isRoot ? "#93c5fd" : "#f1f5f9",
          }}
          title={data.name}
        >
          {data.name}
        </span>
        <span
          style={{
            fontSize: "10px",
            color: "var(--muted, #94a3b8)",
            fontFamily: "var(--font-mono, monospace)",
            whiteSpace: "nowrap",
          }}
        >
          v{data.version}
        </span>
      </div>

      <div
        style={{
          display: "flex",
          gap: "4px",
          alignItems: "center",
          flexWrap: "wrap",
          marginTop: "6px",
        }}
      >
        <span
          style={{
            fontSize: "9px",
            padding: "1px 5px",
            borderRadius: "3px",
            background: data.direct
              ? "rgba(59, 130, 246, 0.2)"
              : "rgba(148, 163, 184, 0.15)",
            color: data.direct ? "#60a5fa" : "#94a3b8",
            fontWeight: 500,
          }}
        >
          {data.isRoot ? "ROOT" : data.direct ? "DIRECT" : "TRANSITIVE"}
        </span>

        {hasVuln && (
          <span
            style={{
              fontSize: "9px",
              padding: "1px 5px",
              borderRadius: "3px",
              background: "rgba(239, 68, 68, 0.2)",
              color: "#f87171",
              fontWeight: 600,
              display: "inline-flex",
              alignItems: "center",
              gap: "2px",
            }}
            title={`${data.advisories.length} OSV vulnerability advisories`}
          >
            <ShieldAlert size={10} />
            {data.advisories.length}
          </span>
        )}

        {hasBehavioral && (
          <span
            style={{
              fontSize: "9px",
              padding: "1px 5px",
              borderRadius: "3px",
              background: "rgba(245, 158, 11, 0.2)",
              color: "#fbbf24",
              fontWeight: 600,
              display: "inline-flex",
              alignItems: "center",
              gap: "2px",
            }}
            title={`${data.behavioralFindings.length} behavioral security findings`}
          >
            <FileCode2 size={10} />
            {data.behavioralFindings.length}
          </span>
        )}

        {data.status && data.status !== "inspected" && !data.isRoot && (
          <span
            style={{
              fontSize: "9px",
              padding: "1px 4px",
              borderRadius: "3px",
              background: "rgba(168, 85, 247, 0.15)",
              color: "#c084fc",
            }}
          >
            {data.status}
          </span>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: "#6366f1", width: 7, height: 7 }}
      />
    </div>
  );
}

const nodeTypes = {
  custom: CustomNode,
};

// Dagre layout computation
function getLayoutedElements(
  nodes: Node[],
  edges: Edge[],
  direction = "TB",
): { nodes: Node[]; edges: Edge[] } {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({
    rankdir: direction,
    nodesep: 40,
    ranksep: 70,
  });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 190, height: 65 });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - 95,
        y: nodeWithPosition.y - 32,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

export default function DependencyGraph({
  report,
  onSelectFinding,
  onAskIntelligence,
  onRemediate,
  selectedPackageName,
}: {
  report: Report;
  onSelectFinding?: (findingId: string) => void;
  onAskIntelligence?: (findingId?: string) => void;
  onRemediate?: (findingId?: string) => void;
  selectedPackageName?: string;
}) {
  const [search, setSearch] = useState(selectedPackageName || "");
  const [filterState, setFilterState] = useState<
    "all" | "vulnerable" | "behavioral" | "direct" | "skipped"
  >("all");
  const [depthLimit, setDepthLimit] = useState<1 | 2 | 99>(
    (report.inspections?.length || report.dependencies.length) > 100 ? 1 : 99,
  );
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [focusedSubtreePackage, setFocusedSubtreePackage] = useState<
    string | null
  >(null);

  // Map findings to packages
  const packageFindings = useMemo(() => {
    const advMap = new Map<string, Finding[]>();
    const behMap = new Map<string, Finding[]>();

    report.findings.forEach((f) => {
      const pkgName = f.package
        ? f.package.split("@")[0]
        : f.evidence[0]?.file.includes("node_modules/")
          ? f.evidence[0].file.split("node_modules/").pop()?.split("/")[0]
          : null;

      if (!pkgName) return;

      if (f.rule === "OSV" || f.domain === "vulnerability" || !!f.advisory) {
        if (!advMap.has(pkgName)) advMap.set(pkgName, []);
        advMap.get(pkgName)!.push(f);
      } else if ((!f.domain || f.domain === "behavior") && f.rule !== "OSV") {
        if (!behMap.has(pkgName)) behMap.set(pkgName, []);
        behMap.get(pkgName)!.push(f);
      }
    });

    return { advMap, behMap };
  }, [report.findings]);

  // Construct raw graph models from inspections & dependencies
  const { rawNodes, rawEdges, childrenMap, parentsMap } = useMemo(() => {
    const rNodes: Array<{
      id: string;
      name: string;
      version: string;
      direct: boolean;
      status: string;
      reason?: string;
      location?: string;
      depth: number;
    }> = [];
    const rEdges: Array<{ id: string; source: string; target: string }> = [];
    const cMap = new Map<string, string[]>();
    const pMap = new Map<string, string[]>();

    const rootId = "root";
    rNodes.push({
      id: rootId,
      name: report.name,
      version: report.version,
      direct: true,
      status: "inspected",
      depth: 0,
      location: "root",
    });

    if (report.inspections && report.inspections.length > 0) {
      const locToId = new Map<string, string>();

      report.inspections.forEach((insp) => {
        const id = insp.location;
        locToId.set(insp.location, id);
        rNodes.push({
          id,
          name: insp.name,
          version: insp.version,
          direct: insp.direct,
          status: insp.status,
          reason: insp.reason,
          location: insp.location,
          depth: insp.depth ?? (insp.direct ? 1 : 2),
        });

        if (insp.direct) {
          rEdges.push({
            id: `e-root-${id}`,
            source: rootId,
            target: id,
          });
          if (!cMap.has(rootId)) cMap.set(rootId, []);
          cMap.get(rootId)!.push(id);
          if (!pMap.has(id)) pMap.set(id, []);
          pMap.get(id)!.push(rootId);
        }
      });

      // Add child dependency edges
      report.inspections.forEach((insp) => {
        const sourceId = insp.location;
        (insp.dependencies || []).forEach((childLoc) => {
          if (locToId.has(childLoc)) {
            const targetId = locToId.get(childLoc)!;
            const edgeId = `e-${sourceId}-${targetId}`;
            rEdges.push({ id: edgeId, source: sourceId, target: targetId });

            if (!cMap.has(sourceId)) cMap.set(sourceId, []);
            cMap.get(sourceId)!.push(targetId);
            if (!pMap.has(targetId)) pMap.set(targetId, []);
            pMap.get(targetId)!.push(sourceId);
          }
        });
      });
    } else {
      // Fallback for reports without lockfile inspections
      report.dependencies.forEach((dep, idx) => {
        const id = `dep-${dep.name}-${idx}`;
        rNodes.push({
          id,
          name: dep.name,
          version: dep.version,
          direct: dep.direct,
          status: "uninspected",
          depth: dep.direct ? 1 : 2,
          location: dep.source,
        });

        if (dep.direct) {
          rEdges.push({ id: `e-root-${id}`, source: rootId, target: id });
          if (!cMap.has(rootId)) cMap.set(rootId, []);
          cMap.get(rootId)!.push(id);
          if (!pMap.has(id)) pMap.set(id, []);
          pMap.get(id)!.push(rootId);
        }
      });
    }

    return {
      rawNodes: rNodes,
      rawEdges: rEdges,
      childrenMap: cMap,
      parentsMap: pMap,
    };
  }, [report]);

  // Filtering, search, and subgraph focusing
  const { filteredNodes, filteredEdges, totalDiscovered } = useMemo(() => {
    let activeNodes = rawNodes;

    // 1. Focus on specific subtree if requested
    if (focusedSubtreePackage) {
      const matchNode = rawNodes.find(
        (n) => n.name.toLowerCase() === focusedSubtreePackage.toLowerCase(),
      );
      if (matchNode) {
        const allowedIds = new Set<string>();
        allowedIds.add("root");
        allowedIds.add(matchNode.id);

        // Add all ancestors up to root
        function addParents(id: string) {
          const parents = parentsMap.get(id) || [];
          parents.forEach((pid) => {
            if (!allowedIds.has(pid)) {
              allowedIds.add(pid);
              addParents(pid);
            }
          });
        }
        addParents(matchNode.id);

        // Add direct children
        (childrenMap.get(matchNode.id) || []).forEach((cid) =>
          allowedIds.add(cid),
        );

        activeNodes = rawNodes.filter((n) => allowedIds.has(n.id));
      }
    } else {
      // 2. Depth Limit filter
      if (depthLimit < 99) {
        activeNodes = activeNodes.filter(
          (n) => n.id === "root" || n.depth <= depthLimit,
        );
      }

      // 3. Status filter
      if (filterState === "vulnerable") {
        const vulnNames = new Set(packageFindings.advMap.keys());
        const allowed = new Set<string>(["root"]);
        activeNodes.forEach((n) => {
          if (vulnNames.has(n.name)) allowed.add(n.id);
        });
        activeNodes = activeNodes.filter((n) => allowed.has(n.id));
      } else if (filterState === "behavioral") {
        const behNames = new Set(packageFindings.behMap.keys());
        const allowed = new Set<string>(["root"]);
        activeNodes.forEach((n) => {
          if (behNames.has(n.name)) allowed.add(n.id);
        });
        activeNodes = activeNodes.filter((n) => allowed.has(n.id));
      } else if (filterState === "direct") {
        activeNodes = activeNodes.filter((n) => n.id === "root" || n.direct);
      } else if (filterState === "skipped") {
        activeNodes = activeNodes.filter(
          (n) =>
            n.id === "root" ||
            n.status === "skipped" ||
            n.status === "unresolved" ||
            n.status === "unavailable",
        );
      }

      // 4. Search query filter
      if (search.trim()) {
        const q = search.toLowerCase();
        const matches = activeNodes.filter(
          (n) =>
            n.name.toLowerCase().includes(q) ||
            n.version.toLowerCase().includes(q),
        );
        const matchIds = new Set(matches.map((n) => n.id));
        matchIds.add("root");

        // Keep direct parents of search results to maintain tree continuity
        matches.forEach((m) => {
          (parentsMap.get(m.id) || []).forEach((pid) => matchIds.add(pid));
        });

        activeNodes = activeNodes.filter((n) => matchIds.has(n.id));
      }
    }

    const activeNodeIdSet = new Set(activeNodes.map((n) => n.id));
    const activeEdges = rawEdges.filter(
      (e) => activeNodeIdSet.has(e.source) && activeNodeIdSet.has(e.target),
    );

    return {
      filteredNodes: activeNodes,
      filteredEdges: activeEdges,
      totalDiscovered: rawNodes.length - 1, // minus root
    };
  }, [
    rawNodes,
    rawEdges,
    focusedSubtreePackage,
    depthLimit,
    filterState,
    search,
    packageFindings,
    parentsMap,
    childrenMap,
  ]);

  // Convert to ReactFlow Nodes and Edges with layout
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    const rfNodes: Node[] = filteredNodes.map((fn) => ({
      id: fn.id,
      type: "custom",
      data: {
        id: fn.id,
        name: fn.name,
        version: fn.version,
        direct: fn.direct,
        status: fn.status,
        reason: fn.reason,
        location: fn.location,
        depth: fn.depth,
        advisories: packageFindings.advMap.get(fn.name) || [],
        behavioralFindings: packageFindings.behMap.get(fn.name) || [],
        isRoot: fn.id === "root",
        isSelected: fn.id === selectedNodeId,
        childCount: (childrenMap.get(fn.id) || []).length,
        parentCount: (parentsMap.get(fn.id) || []).length,
      },
      position: { x: 0, y: 0 },
    }));

    const rfEdges: Edge[] = filteredEdges.map((fe) => ({
      id: fe.id,
      source: fe.source,
      target: fe.target,
      type: "smoothstep",
      animated: fe.source === "root",
      style: { stroke: "#475569", strokeWidth: 1.5 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: 12,
        height: 12,
        color: "#64748b",
      },
    }));

    return getLayoutedElements(rfNodes, rfEdges);
  }, [
    filteredNodes,
    filteredEdges,
    packageFindings,
    selectedNodeId,
    childrenMap,
    parentsMap,
  ]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  // When node is clicked
  const onNodeClick = useCallback((_: any, node: Node) => {
    setSelectedNodeId(node.id);
  }, []);

  // Currently selected node object
  const selectedNodeData = useMemo(() => {
    if (!selectedNodeId) return null;
    const n = nodes.find((node) => node.id === selectedNodeId);
    return (n?.data as DependencyNodeData) || null;
  }, [nodes, selectedNodeId]);

  return (
    <div className="dependency-graph-wrapper">
      {/* Top Toolbar */}
      <div className="graph-toolbar">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            flexWrap: "wrap",
          }}
        >
          {/* Search box */}
          <div
            style={{
              position: "relative",
              display: "flex",
              alignItems: "center",
            }}
          >
            <Search
              size={14}
              style={{
                position: "absolute",
                left: "10px",
                color: "var(--muted)",
              }}
            />
            <input
              type="text"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setFocusedSubtreePackage(null);
              }}
              placeholder="Search package name..."
              style={{
                padding: "6px 28px 6px 30px",
                borderRadius: "6px",
                background: "var(--surface)",
                border: "1px solid var(--line)",
                color: "var(--text)",
                fontSize: "12px",
                width: "180px",
              }}
            />
            {search && (
              <button
                onClick={() => setSearch("")}
                style={{
                  position: "absolute",
                  right: "8px",
                  background: "none",
                  border: "none",
                  color: "var(--muted)",
                  cursor: "pointer",
                }}
              >
                <X size={13} />
              </button>
            )}
          </div>

          {/* Assessment state filter buttons */}
          <div className="dataset-filter-control">
            <button
              className={`dataset-filter-btn ${filterState === "all" ? "active" : ""}`}
              onClick={() => {
                setFilterState("all");
                setFocusedSubtreePackage(null);
              }}
            >
              All ({totalDiscovered})
            </button>
            <button
              className={`dataset-filter-btn ${filterState === "vulnerable" ? "active" : ""}`}
              onClick={() => {
                setFilterState("vulnerable");
                setFocusedSubtreePackage(null);
              }}
            >
              Vulnerable ({packageFindings.advMap.size})
            </button>
            <button
              className={`dataset-filter-btn ${filterState === "behavioral" ? "active" : ""}`}
              onClick={() => {
                setFilterState("behavioral");
                setFocusedSubtreePackage(null);
              }}
            >
              Signals ({packageFindings.behMap.size})
            </button>
            <button
              className={`dataset-filter-btn ${filterState === "direct" ? "active" : ""}`}
              onClick={() => {
                setFilterState("direct");
                setFocusedSubtreePackage(null);
              }}
            >
              Direct
            </button>
          </div>

          {/* Depth limit selector */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <span style={{ fontSize: "11px", color: "var(--muted)" }}>
              Depth:
            </span>
            <select
              value={depthLimit}
              onChange={(e) => {
                setDepthLimit(Number(e.target.value) as any);
                setFocusedSubtreePackage(null);
              }}
              style={{
                padding: "4px 8px",
                borderRadius: "6px",
                background: "var(--surface)",
                border: "1px solid var(--line)",
                color: "var(--text)",
                fontSize: "11px",
              }}
            >
              <option value={1}>Direct Only (Level 1)</option>
              <option value={2}>Depth 2</option>
              <option value={99}>Full Tree (All)</option>
            </select>
          </div>
        </div>

        {/* Right action controls */}
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          {focusedSubtreePackage && (
            <button
              onClick={() => setFocusedSubtreePackage(null)}
              className="button secondary compact"
              style={{ fontSize: "11px", gap: "4px" }}
            >
              <RotateCcw size={12} />
              Reset Focused Subtree
            </button>
          )}

          <span style={{ fontSize: "11px", color: "var(--muted)" }}>
            Showing <strong>{nodes.length - 1}</strong> of{" "}
            <strong>{totalDiscovered}</strong> packages
          </span>
        </div>
      </div>

      {/* Main Canvas + Inspector Split View */}
      <div
        style={{
          display: "flex",
          position: "relative",
          height: "620px",
          overflow: "hidden",
        }}
      >
        <div style={{ flex: 1, height: "100%", background: "#090d16" }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.2}
            maxZoom={1.8}
          >
            <Background color="#1e293b" gap={18} size={1} />
            <Controls
              style={{
                background: "#0f172a",
                border: "1px solid rgba(255, 255, 255, 0.15)",
                borderRadius: "6px",
              }}
            />
            <MiniMap
              style={{
                background: "#0b0f19",
                border: "1px solid rgba(255, 255, 255, 0.1)",
                borderRadius: "6px",
              }}
              nodeColor={(n: any) => {
                if (n.data?.isRoot) return "#3b82f6";
                if (n.data?.advisories?.length > 0) return "#ef4444";
                if (n.data?.behavioralFindings?.length > 0) return "#f59e0b";
                return "#64748b";
              }}
            />
          </ReactFlow>
        </div>

        {/* Selected Package Detail Panel */}
        {selectedNodeData && (
          <aside className="graph-sidebar-panel">
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
              }}
            >
              <div>
                <Eyebrow>PACKAGE INSPECTOR</Eyebrow>
                <h3 style={{ margin: "4px 0 2px", fontSize: "16px" }}>
                  {selectedNodeData.name}
                </h3>
                <span
                  style={{
                    fontSize: "12px",
                    color: "var(--muted)",
                    fontFamily: "monospace",
                  }}
                >
                  version {selectedNodeData.version}
                </span>
              </div>
              <button
                onClick={() => setSelectedNodeId(null)}
                style={{
                  background: "none",
                  border: "none",
                  color: "var(--muted)",
                  cursor: "pointer",
                }}
              >
                <X size={16} />
              </button>
            </div>

            {/* Quick status attributes */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "8px",
                fontSize: "12px",
              }}
            >
              <div
                style={{
                  padding: "8px",
                  borderRadius: "6px",
                  background: "var(--surface-muted, rgba(255,255,255,0.03))",
                  border: "1px solid var(--line)",
                }}
              >
                <span style={{ fontSize: "10px", color: "var(--muted)" }}>
                  Relationship
                </span>
                <strong style={{ display: "block" }}>
                  {selectedNodeData.isRoot
                    ? "Root Workspace"
                    : selectedNodeData.direct
                      ? "Direct Dependency"
                      : "Transitive"}
                </strong>
              </div>

              <div
                style={{
                  padding: "8px",
                  borderRadius: "6px",
                  background: "var(--surface-muted, rgba(255,255,255,0.03))",
                  border: "1px solid var(--line)",
                }}
              >
                <span style={{ fontSize: "10px", color: "var(--muted)" }}>
                  Inspection Status
                </span>
                <strong
                  style={{
                    display: "block",
                    textTransform: "capitalize",
                    color:
                      selectedNodeData.status === "inspected"
                        ? "#10b981"
                        : "#c084fc",
                  }}
                >
                  {selectedNodeData.status}
                </strong>
              </div>
            </div>

            {/* Subgraph Focus Action */}
            {!selectedNodeData.isRoot && (
              <button
                onClick={() => setFocusedSubtreePackage(selectedNodeData.name)}
                className="button secondary compact"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "6px",
                  fontSize: "12px",
                }}
              >
                <Eye size={14} />
                <span>Focus Subtree & Trace to Root</span>
              </button>
            )}

            {/* Known Advisories Section */}
            <div>
              <span
                style={{
                  fontSize: "11px",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  color: "var(--muted)",
                  letterSpacing: "0.05em",
                }}
              >
                KNOWN VULNERABILITIES ({selectedNodeData.advisories.length})
              </span>
              {selectedNodeData.advisories.length === 0 ? (
                <p
                  style={{
                    fontSize: "12px",
                    color: "var(--muted)",
                    margin: "6px 0 0",
                  }}
                >
                  No known vulnerability advisories match this resolved version.
                </p>
              ) : (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px",
                    marginTop: "6px",
                  }}
                >
                  {selectedNodeData.advisories.map((adv) => (
                    <div
                      key={adv.id}
                      style={{
                        padding: "8px 10px",
                        borderRadius: "6px",
                        background: "rgba(239, 68, 68, 0.08)",
                        border: "1px solid rgba(239, 68, 68, 0.25)",
                        fontSize: "12px",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                        }}
                      >
                        <strong style={{ color: "#f87171" }}>
                          {adv.advisory?.id || adv.title}
                        </strong>
                        <Badge severity={adv.severity} size="sm" />
                      </div>
                      <p
                        style={{
                          margin: "4px 0 6px",
                          fontSize: "11px",
                          color: "var(--foreground)",
                          lineHeight: "1.4",
                        }}
                      >
                        {adv.advisory?.summary || adv.explanation}
                      </p>
                      <div
                        style={{
                          display: "flex",
                          gap: "8px",
                          fontSize: "11px",
                        }}
                      >
                        {onSelectFinding && (
                          <button
                            onClick={() => onSelectFinding(adv.id)}
                            style={{
                              background: "none",
                              border: "none",
                              color: "#818cf8",
                              padding: 0,
                              cursor: "pointer",
                              textDecoration: "underline",
                            }}
                          >
                            View Evidence
                          </button>
                        )}
                        {onAskIntelligence && (
                          <button
                            onClick={() => onAskIntelligence(adv.id)}
                            style={{
                              background: "none",
                              border: "none",
                              color: "#818cf8",
                              padding: 0,
                              cursor: "pointer",
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "3px",
                            }}
                          >
                            <Sparkles size={11} />
                            Ask Intelligence
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Behavioral Findings Section */}
            <div>
              <span
                style={{
                  fontSize: "11px",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  color: "var(--muted)",
                  letterSpacing: "0.05em",
                }}
              >
                BEHAVIORAL SIGNALS ({selectedNodeData.behavioralFindings.length}
                )
              </span>
              {selectedNodeData.behavioralFindings.length === 0 ? (
                <p
                  style={{
                    fontSize: "12px",
                    color: "var(--muted)",
                    margin: "6px 0 0",
                  }}
                >
                  No behavioral security signals detected in inspected source.
                </p>
              ) : (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px",
                    marginTop: "6px",
                  }}
                >
                  {selectedNodeData.behavioralFindings.map((bf) => (
                    <div
                      key={bf.id}
                      style={{
                        padding: "8px 10px",
                        borderRadius: "6px",
                        background: "rgba(245, 158, 11, 0.08)",
                        border: "1px solid rgba(245, 158, 11, 0.25)",
                        fontSize: "12px",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                        }}
                      >
                        <strong style={{ color: "#fbbf24" }}>{bf.title}</strong>
                        <Badge severity={bf.severity} size="sm" />
                      </div>
                      <p
                        style={{
                          margin: "4px 0 6px",
                          fontSize: "11px",
                          color: "var(--foreground)",
                          lineHeight: "1.4",
                        }}
                      >
                        {bf.explanation}
                      </p>
                      {onSelectFinding && (
                        <button
                          onClick={() => onSelectFinding(bf.id)}
                          style={{
                            background: "none",
                            border: "none",
                            color: "#818cf8",
                            padding: 0,
                            cursor: "pointer",
                            textDecoration: "underline",
                            fontSize: "11px",
                          }}
                        >
                          View Finding & Evidence
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Downstream and Upstream Connection Counts */}
            <div
              style={{
                borderTop: "1px solid var(--line)",
                paddingTop: "12px",
                display: "flex",
                justifyContent: "space-between",
                fontSize: "11px",
                color: "var(--muted)",
              }}
            >
              <span>{selectedNodeData.parentCount} Upstream Parents</span>
              <span>{selectedNodeData.childCount} Downstream Dependencies</span>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
