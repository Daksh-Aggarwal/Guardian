"use client";

import React, { useState } from "react";
import {
  Info,
  AlertTriangle,
  AlertCircle,
  ShieldAlert,
} from "lucide-react";
import {
  ShieldCheck,
  ArrowUpRight,
  CheckCircle2,
  HelpCircle,
  Activity,
  Layers,
  ChevronRight,
  Sparkles,
  ShieldCheckIcon,
} from "@/components/icons";
import { motion } from "framer-motion";
import type { Severity } from "@/lib/types";

export function Brand({ size = "default" }: { size?: "default" | "compact" }) {
  const pixelSize = size === "compact" ? 20 : 24;
  return (
    <div className={size === "compact" ? "brand brand-compact" : "brand"}>
      <motion.span
        className="brand-icon flex items-center justify-center"
        whileHover={{ scale: 1.06, rotate: -3 }}
        transition={{ type: "spring", stiffness: 400, damping: 15 }}
      >
        <ShieldCheckIcon size={pixelSize} className="inline-flex items-center justify-center" />
      </motion.span>
      <span className="brand-text">
        guardian<span className="brand-dot">.</span>
      </span>
    </div>
  );
}

export function Badge({
  severity,
  size = "default",
}: {
  severity: Severity | string;
  size?: "default" | "sm";
}) {
  const norm = (severity || "info").toLowerCase();
  const label =
    norm === "info"
      ? "Observation"
      : norm.charAt(0).toUpperCase() + norm.slice(1);
  return (
    <span className={size === "sm" ? `badge ${norm} badge-sm` : `badge ${norm}`}>
      <i className="badge-dot" />
      {label}
    </span>
  );
}

export function StatusChip({
  status,
  label,
  tone = "neutral",
}: {
  status?: string;
  label?: string;
  tone?: "danger" | "warning" | "success" | "info" | "neutral" | "purple";
}) {
  const text = label || (status ? status.replaceAll("_", " ") : "unknown");
  const computedTone =
    tone !== "neutral"
      ? tone
      : status === "verified" || status === "complete" || status === "checked"
        ? "success"
        : status === "mismatch" || status === "integrity_failed"
          ? "danger"
          : status === "skipped" ||
              status === "partial" ||
              status === "incomplete"
            ? "warning"
            : status === "manifest_only" || status === "unavailable"
              ? "purple"
              : "neutral";

  return (
    <span className={`status-chip status-${computedTone}`}>
      <i className="status-dot" />
      {text}
    </span>
  );
}

export function Eyebrow({ children }: { children: React.ReactNode }) {
  return <div className="eyebrow">{children}</div>;
}

export function ClassificationBadge({
  classification,
  size = "default",
}: {
  classification?: "real" | "demo" | string;
  size?: "default" | "sm";
}) {
  const isDemo = classification === "demo";
  return (
    <span
      className={
        size === "sm"
          ? `classification-badge ${isDemo ? "demo" : "real"} badge-sm`
          : `classification-badge ${isDemo ? "demo" : "real"}`
      }
      title={
        isDemo ? "Synthetic demonstration fixture" : "Real project / package"
      }
    >
      <i className="classification-dot" />
      {isDemo ? "Demo Fixture" : "Real Project"}
    </span>
  );
}

export function Empty({
  title,
  children,
  action,
}: {
  title: string;
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon-wrap">
        <ShieldCheck size={32} strokeWidth={1.5} />
      </div>
      <h3>{title}</h3>
      <p>{children}</p>
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}

export function Note({
  children,
  variant = "info",
}: {
  children: React.ReactNode;
  variant?: "info" | "warning" | "success";
}) {
  const Icon =
    variant === "warning"
      ? AlertTriangle
      : variant === "success"
        ? CheckCircle2
        : Info;
  return (
    <div className={`note note-${variant}`}>
      <Icon size={16} className="note-icon" />
      <div className="note-content">{children}</div>
    </div>
  );
}

export function External({
  href,
  children,
}: {
  href: string;
  children: React.ReactNode;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="text-link inline-external"
    >
      <span>{children}</span>
      <ArrowUpRight size={13} />
    </a>
  );
}

export function SectionHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="section-header">
      <div className="section-header-text">
        {eyebrow && <Eyebrow>{eyebrow}</Eyebrow>}
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {action && <div className="section-header-action">{action}</div>}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  icon,
  detail,
  status = "neutral",
  onClick,
}: {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  detail: string;
  status?: "danger" | "warning" | "success" | "info" | "neutral";
  onClick?: () => void;
}) {
  const content = (
    <div
      className={`metric-card status-${status} ${onClick ? "interactive" : ""}`}
    >
      <div className="metric-header">
        <span className="metric-label">{label}</span>
        <div className="metric-icon-wrap">{icon}</div>
      </div>
      <div className="metric-value-row">
        <strong className="metric-value">
          {typeof value === "number" && value < 10 && value >= 0
            ? String(value).padStart(2, "0")
            : value}
        </strong>
      </div>
      <p className="metric-detail">{detail}</p>
    </div>
  );

  if (onClick) {
    return (
      <button type="button" onClick={onClick} className="metric-card-btn">
        {content}
      </button>
    );
  }
  return content;
}

export function SecurityDimensionCard({
  title,
  domain,
  status,
  statusTone,
  headline,
  description,
  metric,
  metricLabel,
  icon,
  onClick,
}: {
  title: string;
  domain: string;
  status: string;
  statusTone: "danger" | "warning" | "success" | "info" | "neutral" | "purple";
  headline: string;
  description: string;
  metric?: string | number;
  metricLabel?: string;
  icon: React.ReactNode;
  onClick?: () => void;
}) {
  return (
    <div
      className={`dimension-card tone-${statusTone} ${onClick ? "interactive" : ""}`}
      onClick={onClick}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={
        onClick
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onClick();
              }
            }
          : undefined
      }
    >
      <div className="dimension-card-top">
        <div className="dimension-icon-wrap">{icon}</div>
        <div className="dimension-title-area">
          <span className="dimension-domain">{domain}</span>
          <h3 className="dimension-title">{title}</h3>
        </div>
        <StatusChip status={status} tone={statusTone} />
      </div>

      <div className="dimension-body">
        <strong className="dimension-headline">{headline}</strong>
        <p className="dimension-description">{description}</p>
      </div>

      {(metric !== undefined || onClick) && (
        <div className="dimension-footer">
          {metric !== undefined && (
            <div className="dimension-stat">
              <strong>{metric}</strong>
              <span>{metricLabel}</span>
            </div>
          )}
          {onClick && (
            <span className="dimension-action-link">
              Inspect details <ChevronRight size={13} />
            </span>
          )}
        </div>
      )}
    </div>
  );
}

export function RecommendedActionCard({
  priority,
  project,
  title,
  reason,
  actionLabel = "Investigate finding",
  onClick,
}: {
  priority: "critical" | "high" | "medium" | "low" | "info";
  project: string;
  title: string;
  reason: string;
  actionLabel?: string;
  onClick: () => void;
}) {
  return (
    <div className={`action-card priority-${priority}`}>
      <div className="action-card-header">
        <div className="action-card-meta">
          <Badge severity={priority} size="sm" />
          <span className="action-project-name">{project}</span>
        </div>
      </div>
      <h4 className="action-card-title">{title}</h4>
      <p className="action-card-reason">{reason}</p>
      <button type="button" className="action-card-btn" onClick={onClick}>
        <span>{actionLabel}</span>
        <ChevronRight size={14} />
      </button>
    </div>
  );
}
