import { ShieldCheck, ArrowUpRight, Info } from "lucide-react";
import type { Severity } from "@/lib/types";
export function Brand() {
  return (
    <div className="brand">
      <span className="brand-icon">
        <ShieldCheck size={23} />
      </span>
      <span>
        guardian<span className="brand-dot">.</span>
      </span>
    </div>
  );
}
export function Badge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge ${severity}`}>
      <i />
      {severity === "info" ? "Observation" : severity}
    </span>
  );
}
export function Eyebrow({ children }: { children: React.ReactNode }) {
  return <div className="eyebrow">{children}</div>;
}
export function Empty({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="empty">
      <ShieldCheck size={30} />
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
export function Note({ children }: { children: React.ReactNode }) {
  return (
    <div className="note">
      <Info size={16} />
      <span>{children}</span>
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
    <a href={href} target="_blank" rel="noreferrer" className="text-link">
      {children}
      <ArrowUpRight size={14} />
    </a>
  );
}
