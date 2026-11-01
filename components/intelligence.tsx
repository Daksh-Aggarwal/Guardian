"use client";
import { useState } from "react";
import { Info, FileCode2 } from "lucide-react";
import { GitBranch, ShieldCheck, Package, Search } from "@/components/icons";
import { Report, Finding, Integrity } from "@/lib/types";
import { Eyebrow, Note } from "./ui";

export function IntelligenceOverview({ report }: { report: Report }) {
  const summary = report.inspection_summary;
  if (report.engine_version !== "2") return null;
  const vulnerabilities =
    report.assessments?.vulnerabilities?.count ??
    report.findings.filter((f) => f.rule === "OSV").length;
  const integrityConcerns =
    report.assessments?.integrity?.concerns ??
    report.findings.filter((f) => f.domain === "integrity").length;
  const totalDeps = summary?.total ?? 0;
  return (
    <div
      className="intelligence-overview"
      aria-label="Independent assessment areas"
    >
      <div>
        <Info size={17} />
        <Eyebrow>KNOWN VULNERABILITIES</Eyebrow>
        <strong>
          {vulnerabilities} advisory{" "}
          {vulnerabilities === 1 ? "match" : "matches"}
        </strong>
        <p>
          Intelligence {report.intelligence}. Separate from suspected behavior.
        </p>
      </div>
      <div>
        <ShieldCheck size={17} />
        <Eyebrow>PACKAGE INTEGRITY</Eyebrow>
        <strong>
          {integrityConcerns
            ? `${integrityConcerns} integrity ${integrityConcerns === 1 ? "concern" : "concerns"}`
            : report.root_integrity
              ? `Published checksum: ${report.root_integrity.status}`
              : totalDeps > 0
                ? "See dependency checksums"
                : "No external tarballs"}
        </strong>
        <p>
          A matching checksum establishes byte consistency, not software safety.
        </p>
      </div>
      <div>
        <Package size={17} />
        <Eyebrow>SOURCE INSPECTION</Eyebrow>
        <strong>
          {summary?.inspected ?? 0} / {totalDeps} dependencies inspected
        </strong>
        <p>
          {summary?.skipped ?? 0} skipped (budget) · {summary?.unavailable ?? 0}{" "}
          unavailable · {summary?.unresolved ?? 0} unresolved
          {(summary?.integrity_failed ?? 0) > 0
            ? ` · ${summary?.integrity_failed} integrity failed`
            : ""}
          {(summary?.not_attempted ?? 0) > 0
            ? ` · ${summary?.not_attempted} not attempted`
            : ""}
        </p>
      </div>
    </div>
  );
}
export function IntegrityDetails({
  integrity,
  label,
  advanced,
}: {
  integrity: Integrity;
  label: string;
  advanced: boolean;
}) {
  return (
    <div className={`integrity-detail ${integrity.status}`}>
      <div>
        <strong>{label}</strong>
        <span className="status-chip">{integrity.status}</span>
      </div>
      <p>{integrity.detail}</p>
      {advanced && (
        <dl>
          <dt>Source / algorithm</dt>
          <dd>
            {integrity.source} / {integrity.algorithm || "not verified"}
          </dd>
          <dt>Expected</dt>
          <dd>
            <code>{integrity.expected || "Not supplied"}</code>
          </dd>
          <dt>Computed</dt>
          <dd>
            <code>{integrity.computed.join("\n") || "Not computed"}</code>
          </dd>
        </dl>
      )}
    </div>
  );
}
export function DependencyInspection({
  report,
  advanced,
}: {
  report: Report;
  advanced: boolean;
}) {
  const [search, setSearch] = useState("");
  const nodes = report.inspections || [],
    summary = report.inspection_summary;
  const visible = nodes.filter((n) =>
    (n.name + " " + n.status).toLowerCase().includes(search.toLowerCase()),
  );
  return (
    <section className="card dependency-card">
      <div className="section-heading">
        <div>
          <h3>What was actually inspected</h3>
          <p>Downloaded code is inspected without installation or execution.</p>
        </div>
        <span className="small-label">{summary?.profile || "fast"} budget</span>
      </div>
      {report.root_integrity && (
        <IntegrityDetails
          integrity={report.root_integrity}
          label="Selected package"
          advanced={advanced}
        />
      )}
      {summary && (
        <div className="inspection-counts">
          {[
            ["Direct", summary.direct],
            ["Transitive", summary.transitive],
            ["Inspected", summary.inspected],
            ["Skipped (budget)", summary.skipped],
            ["Unavailable", summary.unavailable],
            ["Unresolved", summary.unresolved ?? 0],
            ["Integrity failed", summary.integrity_failed ?? 0],
            ["Not attempted", summary.not_attempted ?? 0],
            ["With findings", summary.packages_with_findings],
          ].map(([label, value]) => (
            <div key={label as string}>
              <strong>{value}</strong>
              <span>{label}</span>
            </div>
          ))}
        </div>
      )}
      {!advanced && summary && summary.inspected < summary.total && (
        <Note>
          Guardian inspected {summary.inspected} of {summary.total} dependency
          locations ({summary.direct} direct, {summary.transitive} transitive).{" "}
          {summary.skipped > 0
            ? `${summary.skipped} skipped by budget profile. `
            : ""}
          {summary.unavailable > 0
            ? `${summary.unavailable} unavailable from registry. `
            : ""}
          {summary.unresolved > 0
            ? `${summary.unresolved} unresolved from manifests. `
            : ""}
          {summary.integrity_failed > 0
            ? `${summary.integrity_failed} failed checksum verification. `
            : ""}
          {summary.not_attempted > 0
            ? `${summary.not_attempted} not attempted. `
            : ""}
          Uninspected dependencies are not certified safe and may contain hidden
          behaviors.
        </Note>
      )}
      {!!nodes.length && (
        <div className="history-search">
          <Search size={16} />
          <input
            aria-label="Search dependency inspections"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Name or inspection status…"
          />
        </div>
      )}
      <div className="inspection-list">
        {visible.slice(0, 100).map((n, i) => (
          <details key={n.location + i}>
            <summary>
              <Package size={15} />
              <span>
                <strong>{n.name}</strong>
                <small>
                  {n.version} · {n.direct ? "Direct" : "Transitive"}
                  {advanced && n.depth !== null ? ` · depth ${n.depth}` : ""}
                </small>
              </span>
              <span className={`status-chip ${n.status}`}>
                {n.status.replaceAll("_", " ")}
              </span>
            </summary>
            <div className="inspection-body">
              <p>{n.reason}</p>
              <IntegrityDetails
                integrity={n.integrity}
                label="Lockfile checksum"
                advanced={advanced}
              />
              {n.registry_integrity && (
                <IntegrityDetails
                  integrity={n.registry_integrity}
                  label="Registry checksum"
                  advanced={advanced}
                />
              )}
              <p>
                {n.finding_ids.length} recorded findings.{" "}
                {n.status !== "inspected"
                  ? "Source remains uninspected."
                  : "Check finding details and source coverage before making a decision."}
              </p>
              {advanced && (
                <>
                  <code className="module-path">{n.location}</code>
                  <p>
                    Dependency edges:{" "}
                    {n.dependencies.length
                      ? n.dependencies.join(", ")
                      : "none recorded"}
                  </p>
                </>
              )}
            </div>
          </details>
        ))}
      </div>
      {visible.length > 100 && (
        <Note>
          Showing 100 of {visible.length} matching locations. Search to narrow
          this view; the JSON export contains the full recorded inventory.
        </Note>
      )}
      {!nodes.length && (
        <Note>
          No dependency source locations were available in this input. This does
          not establish that external code is safe.
        </Note>
      )}
      {advanced && summary && (
        <div className="inspection-metrics">
          {summary.registry_requests} registry requests ·{" "}
          {(summary.downloaded_bytes / 1024).toFixed(1)} KB downloaded ·{" "}
          {(summary.elapsed_ms / 1000).toFixed(2)}s dependency inspection
        </div>
      )}
    </section>
  );
}
export function FlowEvidence({
  finding,
  advanced,
}: {
  finding: Finding;
  advanced: boolean;
}) {
  if (!finding.data_flows?.length) return null;
  return (
    <div className="flow-evidence">
      <div className="evidence-heading">
        <h4>
          <GitBranch size={14} /> How the information moves
        </h4>
        <span className="status-chip">Statically inferred</span>
      </div>
      <p>
        This is a possible path through the source, not proof that the software
        ran or sent data.
      </p>
      {finding.data_flows.map((flow, index) => {
        const middle = flow.steps.find(
          (s) => s.kind === "parameter" || s.kind === "assignment",
        );
        const simple =
          flow.steps.length <= 2
            ? flow.steps
            : [
                flow.steps[0],
                ...(middle &&
                middle !== flow.steps[0] &&
                middle !== flow.steps[flow.steps.length - 1]
                  ? [middle]
                  : []),
                flow.steps[flow.steps.length - 1],
              ];
        return (
          <div className="flow-path" key={index}>
            <span className="small-label">
              PATH {index + 1} ·{" "}
              {flow.context === "authentication"
                ? "AUTHENTICATION CONTEXT"
                : "OUTBOUND DATA"}
            </span>
            <ol>
              {(advanced ? flow.steps : simple).map((step, i) => (
                <li key={i}>
                  <span className="flow-marker">{i + 1}</span>
                  <div>
                    <strong>
                      {advanced
                        ? step.detail
                        : step.kind === "source"
                          ? `Private information is read (${step.binding || "environment"})`
                          : step.kind === "sink"
                            ? "Information reaches a network request"
                            : step.kind === "parameter"
                              ? "Passed as argument into function parameter"
                              : step.kind === "assignment"
                                ? "Assigned to variable"
                                : "Information is propagated"}
                    </strong>
                    <span className="flow-location">
                      <FileCode2 size={12} />
                      {step.file}:{step.line}
                      {advanced ? `:${step.column}` : ""}
                    </span>
                    {advanced && (
                      <>
                        <pre>
                          <code>{step.snippet}</code>
                        </pre>
                        {step.binding && <small>Binding: {step.binding}</small>}
                      </>
                    )}
                  </div>
                </li>
              ))}
            </ol>
            {advanced && flow.limitations && flow.limitations.length > 0 && (
              <div className="finding-limitations">
                <h4>Path limitations</h4>
                {flow.limitations.map((lim, li) => (
                  <p key={li}>{lim}</p>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
export function AdvisoryDetails({
  finding,
  advanced,
}: {
  finding: Finding;
  advanced: boolean;
}) {
  const advisory = finding.advisory;
  if (!advisory) return null;
  return (
    <div className="advisory-details">
      <Eyebrow>PUBLISHED VULNERABILITY · {advisory.id}</Eyebrow>
      <dl>
        <dt>Advisory severity</dt>
        <dd>{advisory.severity || "Not supplied / unavailable"}</dd>
        <dt>Guardian review priority</dt>
        <dd>
          {finding.severity}
          {!advisory.severity ? " (review default)" : ""}
        </dd>
        <dt>Detail availability</dt>
        <dd>{advisory.detail_status}</dd>
      </dl>
      {advisory.fixed_versions.length > 0 && (
        <p>
          Published fixed-release boundaries:{" "}
          <strong>{advisory.fixed_versions.join(", ")}</strong>. Check the
          advisory’s affected range before choosing an upgrade.
        </p>
      )}
      {advanced && (
        <>
          <h4>CVSS as published</h4>
          {advisory.cvss.length ? (
            advisory.cvss.map((v, i) => (
              <pre key={i}>
                <code>
                  {v.type}: {v.score}
                </code>
              </pre>
            ))
          ) : (
            <p>No CVSS value was supplied or retrieved.</p>
          )}
          <h4>Affected ranges</h4>
          <pre>
            <code>{JSON.stringify(advisory.affected_ranges, null, 2)}</code>
          </pre>
          {advisory.aliases.length > 0 && (
            <p>Aliases: {advisory.aliases.join(", ")}</p>
          )}
        </>
      )}
    </div>
  );
}
