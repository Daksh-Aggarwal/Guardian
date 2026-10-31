"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  Loader2,
  Shield,
  PlusCircle,
  AlertTriangle,
  Info,
  FileCode2,
} from "lucide-react";
import {
  Sparkles,
  ArrowUp,
  ChevronRight,
  ShieldCheck,
  RotateCcw,
  CheckCircle2,
  X,
  HelpCircle,
  Minimize2,
  ExternalLink,
  SparklesIcon,
} from "@/components/icons";
import { motion, AnimatePresence } from "framer-motion";
import {
  api,
  Report,
  Finding,
  ConversationMessage,
  ConversationSession,
  AdvisorResponse,
  AIStatus,
  FindingCitation,
} from "@/lib/types";
import { Badge, StatusChip } from "./ui";

// Safe, lightweight markdown renderer
function renderMarkdown(
  text: string,
  onCitationClick?: (findingId: string) => void,
) {
  const lines = text.split("\n");
  const elements: React.ReactNode[] = [];
  let inCodeBlock = false;
  let codeBlockContent: string[] = [];
  let bulletItems: string[] = [];
  let numberedItems: string[] = [];

  function flushLists() {
    if (bulletItems.length > 0) {
      elements.push(
        <ul key={`ul-${elements.length}`} className="md-ul">
          {bulletItems.map((item, idx) => (
            <li key={idx}>{parseInlineMarkdown(item, onCitationClick)}</li>
          ))}
        </ul>,
      );
      bulletItems = [];
    }
    if (numberedItems.length > 0) {
      elements.push(
        <ol key={`ol-${elements.length}`} className="md-ol">
          {numberedItems.map((item, idx) => (
            <li key={idx}>{parseInlineMarkdown(item, onCitationClick)}</li>
          ))}
        </ol>,
      );
      numberedItems = [];
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    if (rawLine.startsWith("```")) {
      if (inCodeBlock) {
        elements.push(
          <pre key={`code-${elements.length}`} className="md-codeblock">
            <code>{codeBlockContent.join("\n")}</code>
          </pre>,
        );
        codeBlockContent = [];
        inCodeBlock = false;
      } else {
        flushLists();
        inCodeBlock = true;
      }
      continue;
    }

    if (inCodeBlock) {
      codeBlockContent.push(rawLine);
      continue;
    }

    const numMatch = trimmed.match(/^(\d+)\.\s+(.*)$/);
    if (numMatch) {
      if (bulletItems.length > 0) flushLists();
      numberedItems.push(numMatch[2]);
      continue;
    }

    if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
      if (numberedItems.length > 0) flushLists();
      bulletItems.push(trimmed.substring(2));
      continue;
    }

    flushLists();

    if (!trimmed) continue;

    if (trimmed.startsWith("### ")) {
      elements.push(
        <h4 key={`h3-${elements.length}`} className="md-h4">
          {parseInlineMarkdown(trimmed.substring(4), onCitationClick)}
        </h4>,
      );
      continue;
    }
    if (trimmed.startsWith("## ")) {
      elements.push(
        <h3 key={`h2-${elements.length}`} className="md-h3">
          {parseInlineMarkdown(trimmed.substring(3), onCitationClick)}
        </h3>,
      );
      continue;
    }
    if (trimmed.startsWith("# ")) {
      elements.push(
        <h3 key={`h1-${elements.length}`} className="md-h3">
          {parseInlineMarkdown(trimmed.substring(2), onCitationClick)}
        </h3>,
      );
      continue;
    }

    if (trimmed.startsWith("> ")) {
      elements.push(
        <blockquote key={`quote-${elements.length}`} className="md-quote">
          {parseInlineMarkdown(trimmed.substring(2), onCitationClick)}
        </blockquote>,
      );
      continue;
    }

    elements.push(
      <p key={`p-${elements.length}`} className="md-p">
        {parseInlineMarkdown(trimmed, onCitationClick)}
      </p>,
    );
  }

  flushLists();
  if (inCodeBlock && codeBlockContent.length > 0) {
    elements.push(
      <pre key={`code-${elements.length}`} className="md-codeblock">
        <code>{codeBlockContent.join("\n")}</code>
      </pre>,
    );
  }

  return <div className="markdown-content">{elements}</div>;
}

function parseInlineMarkdown(
  text: string,
  onCitationClick?: (findingId: string) => void,
): React.ReactNode[] {
  const parts = text.split(
    /(`[^`]+`|\*\*[^*]+\*\*|(?<!\*)\*[^*]+\*(?!\*)|\[[^\]]+\]\([^)]+\))/g,
  );
  return parts.map((part, index) => {
    if (!part) return null;
    if (part.startsWith("`") && part.endsWith("`") && part.length >= 2) {
      return (
        <code key={index} className="md-inline-code">
          {part.slice(1, -1)}
        </code>
      );
    }
    if (part.startsWith("**") && part.endsWith("**") && part.length >= 4) {
      return <strong key={index}>{part.slice(2, -2)}</strong>;
    }
    if (
      part.startsWith("*") &&
      part.endsWith("*") &&
      part.length >= 2 &&
      !part.startsWith("**")
    ) {
      return <em key={index}>{part.slice(1, -1)}</em>;
    }
    const linkMatch = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
    if (linkMatch) {
      const linkText = linkMatch[1];
      const linkHref = linkMatch[2];

      // If this is a finding citation link e.g. #finding-id
      if (linkHref.startsWith("#finding-") && onCitationClick) {
        const fId = linkHref.replace("#finding-", "");
        return (
          <button
            key={index}
            type="button"
            className="citation-inline-btn"
            onClick={() => onCitationClick(fId)}
          >
            {linkText}
          </button>
        );
      }

      return (
        <a
          key={index}
          href={linkHref}
          target="_blank"
          rel="noopener noreferrer"
          className="text-link inline-external"
        >
          {linkText}
        </a>
      );
    }
    return part;
  });
}

export default function IntelligencePanel({
  report,
  isOpen,
  onClose,
  selectedFinding,
  onClearSelectedFinding,
  onFocusFinding,
  advanced = false,
}: {
  report: Report;
  isOpen: boolean;
  onClose: () => void;
  selectedFinding?: Finding | null;
  onClearSelectedFinding?: () => void;
  onFocusFinding?: (findingId: string) => void;
  advanced?: boolean;
}) {
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ConversationMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [aiStatus, setAiStatus] = useState<AIStatus | null>(null);
  const [consent, setConsent] = useState(false);
  const [showPrivacyBanner, setShowPrivacyBanner] = useState(false);
  const [expandedCitations, setExpandedCitations] = useState<
    Record<string, boolean>
  >({});

  const feedRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Initialize consent and AI status
  useEffect(() => {
    try {
      const stored = localStorage.getItem("guardian_ai_consent");
      if (stored === "true") setConsent(true);
    } catch {}

    api<AIStatus>("/ai/status")
      .then(setAiStatus)
      .catch(() => {});
  }, []);

  // Fetch or initialize conversation
  useEffect(() => {
    if (!report?.id) return;
    let active = true;
    api<ConversationSession>(`/scans/${report.id}/conversation`)
      .then((session) => {
        if (active) {
          setConversationId(session.id);
          setMessages(session.messages || []);
        }
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [report.id]);

  // Auto-scroll feed on new message
  useEffect(() => {
    if (feedRef.current && messages.length > 0) {
      feedRef.current.scrollTo({
        top: feedRef.current.scrollHeight,
        behavior: "smooth",
      });
    }
  }, [messages.length, busy]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 200);
    }
  }, [isOpen, selectedFinding]);

  function handleConsentChange(value: boolean) {
    setConsent(value);
    try {
      localStorage.setItem("guardian_ai_consent", value ? "true" : "false");
    } catch {}
  }

  async function sendMessage(questionText: string) {
    const q = questionText.trim();
    if (!q || busy) return;

    setBusy(true);
    setError(null);

    const tempUserMsg: ConversationMessage = {
      id: "temp-" + Date.now(),
      conversation_id: conversationId || "new",
      scan_id: report.id,
      role: "user",
      content: q,
      citations: [],
      limitations: [],
      suggested_followups: [],
      provider: aiStatus?.enabled && consent ? "gemini" : "deterministic",
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, tempUserMsg]);
    setInput("");

    try {
      const payload: {
        question: string;
        consent: boolean;
        conversation_id?: string | null;
        finding_id?: string | null;
        mode: "simple" | "advanced";
      } = {
        question: q,
        consent: consent,
        conversation_id: conversationId,
        finding_id: selectedFinding?.id || null,
        mode: advanced ? "advanced" : "simple",
      };

      const response = await api<AdvisorResponse>(
        `/scans/${report.id}/conversation/message`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        },
      );

      setConversationId(response.conversation_id);

      const assistantMsg: ConversationMessage = {
        id: response.message_id,
        conversation_id: response.conversation_id,
        scan_id: report.id,
        role: "assistant",
        content: response.answer,
        citations: response.citations || [],
        limitations: response.limitations || [],
        suggested_followups: response.suggested_followups || [],
        provider: response.provider,
        model: response.model,
        created_at: new Date().toISOString(),
      };

      setMessages((prev) => [
        ...prev.filter((m) => m.id !== tempUserMsg.id),
        tempUserMsg,
        assistantMsg,
      ]);
    } catch (err) {
      setError((err as Error).message || "Failed to retrieve explanation.");
      setMessages((prev) => prev.filter((m) => m.id !== tempUserMsg.id));
      setInput(q);
    } finally {
      setBusy(false);
    }
  }

  async function handleClearConversation() {
    try {
      await api(`/scans/${report.id}/conversation`, { method: "DELETE" });
      setMessages([]);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function handleNewConversation() {
    try {
      const res = await api<ConversationSession>(
        `/scans/${report.id}/conversation/new`,
        { method: "POST" },
      );
      setConversationId(res.id);
      setMessages([]);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  // Dynamic suggested prompts
  const dynamicSuggestions: string[] = [];
  if (selectedFinding) {
    dynamicSuggestions.push(`Why is this finding dangerous?`);
    if (selectedFinding.advisory || selectedFinding.rule === "OSV") {
      dynamicSuggestions.push(`Does this vulnerability affect our version?`);
    }
    dynamicSuggestions.push(`Explain this finding in simple language`);
    dynamicSuggestions.push(
      `What practical steps should we take to resolve this?`,
    );
  } else {
    const highFinding = report.findings.find((f) =>
      ["high", "critical"].includes(f.severity),
    );
    const hasAdvisories = report.findings.some(
      (f) => f.rule === "OSV" || f.advisory,
    );
    const dataFlowFinding = report.findings.find(
      (f) => f.data_flows && f.data_flows.length > 0,
    );

    if (highFinding) {
      dynamicSuggestions.push(`Why is "${highFinding.title}" dangerous?`);
    }
    if (hasAdvisories) {
      dynamicSuggestions.push(
        `Do the advisories apply to our installed version?`,
      );
    }
    if (dataFlowFinding) {
      dynamicSuggestions.push(`Explain the sensitive data-flow path`);
    }
    dynamicSuggestions.push(`What should we investigate first?`);
    if (
      report.coverage.some(
        (c) => c.includes("skipped") || c.includes("unavailable"),
      )
    ) {
      dynamicSuggestions.push(`What did Guardian fail to inspect?`);
    } else {
      dynamicSuggestions.push(`Is this package safe to use in production?`);
    }
  }

  const suggestionsToShow = dynamicSuggestions.slice(0, 3);
  const activeProvider =
    aiStatus?.enabled && consent ? "gemini" : "deterministic";
  const activeModel = aiStatus?.model || "gemini-3.8-flash";

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Overlay for smaller screens */}
          <motion.div
            className="copilot-backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />

          <motion.aside
            className="copilot-panel"
            initial={{ x: "100%", opacity: 0.5 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: "100%", opacity: 0 }}
            transition={{ type: "spring", stiffness: 350, damping: 30 }}
            aria-label="Guardian Intelligence Panel"
          >
            {/* Header */}
            <div className="copilot-header">
              <div className="copilot-brand">
                <div className="copilot-icon-wrap">
                  <SparklesIcon size={16} className="copilot-spark-icon inline-flex items-center justify-center" />
                  <span className="copilot-pulse" />
                </div>
                <div>
                  <h3 className="copilot-title">Guardian Intelligence</h3>
                  <div className="copilot-meta">
                    <span className={`status-pill pill-${activeProvider}`}>
                      {activeProvider === "gemini"
                        ? activeModel
                        : "Deterministic Engine"}
                    </span>
                    <button
                      type="button"
                      className="privacy-toggle-btn"
                      onClick={() => setShowPrivacyBanner((p) => !p)}
                      title="Privacy & AI consent settings"
                    >
                      {consent ? (
                        <ShieldCheck size={12} className="text-emerald" />
                      ) : (
                        <Shield size={12} />
                      )}
                      <span>{consent ? "AI Enabled" : "Privacy / Local"}</span>
                    </button>
                  </div>
                </div>
              </div>

              <div className="copilot-header-actions">
                {messages.length > 0 && (
                  <>
                    <button
                      type="button"
                      className="copilot-tool-btn"
                      onClick={handleNewConversation}
                      disabled={busy}
                      title="Start fresh conversation"
                    >
                      <PlusCircle size={15} />
                    </button>
                    <button
                      type="button"
                      className="copilot-tool-btn"
                      onClick={handleClearConversation}
                      disabled={busy}
                      title="Clear messages"
                    >
                      <RotateCcw size={15} />
                    </button>
                  </>
                )}
                <button
                  type="button"
                  className="copilot-close-btn"
                  onClick={onClose}
                  aria-label="Close Intelligence panel"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Privacy & Boundary Drawer */}
            <AnimatePresence>
              {showPrivacyBanner && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="copilot-privacy-box"
                >
                  <div className="privacy-box-header">
                    <Shield size={14} />
                    <strong>Privacy-First Evidence Boundary</strong>
                  </div>
                  <p>
                    Guardian never sends your project archives or full source
                    tree. When Gemini AI is enabled:
                  </p>
                  <ul>
                    <li>
                      Code snippets are redacted for secrets, keys, and tokens.
                    </li>
                    <li>
                      Context is restricted to verified findings and advisories.
                    </li>
                    <li>The deterministic engine remains authoritative.</li>
                  </ul>
                  <label className="privacy-checkbox-label">
                    <input
                      type="checkbox"
                      checked={consent}
                      onChange={(e) => handleConsentChange(e.target.checked)}
                    />
                    <span>
                      Enable Google Gemini ({activeModel}) for explanatory
                      insights
                    </span>
                  </label>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Active Context Banner */}
            {selectedFinding ? (
              <div className="copilot-context-banner active">
                <div className="context-banner-content">
                  <span className="context-tag">Active Context</span>
                  <div className="context-title-row">
                    <strong
                      className="context-title"
                      title={selectedFinding.title}
                    >
                      {selectedFinding.title}
                    </strong>
                    <Badge severity={selectedFinding.severity} size="sm" />
                  </div>
                </div>
                {onClearSelectedFinding && (
                  <button
                    type="button"
                    className="clear-context-btn"
                    onClick={onClearSelectedFinding}
                    title="Clear finding context and ask about entire report"
                  >
                    <X size={13} />
                  </button>
                )}
              </div>
            ) : (
              <div className="copilot-context-banner report-scope">
                <span className="context-tag">Scope</span>
                <span className="context-title">
                  Entire Report: <strong>{report.name}</strong> (
                  {report.version})
                </span>
              </div>
            )}

            {/* Conversation Feed */}
            <div className="copilot-feed" ref={feedRef}>
              {messages.length === 0 ? (
                <div className="copilot-empty">
                  <div className="copilot-empty-icon">
                    <SparklesIcon size={26} className="inline-flex items-center justify-center text-amber-400" />
                  </div>
                  <h4>Evidence-Grounded Security Advisor</h4>
                  <p>
                    Ask questions about findings, attack implications, or
                    remediation. Answers cite verified evidence from this scan.
                  </p>

                  <div className="copilot-prompt-suggestions">
                    <span className="suggestions-label">
                      Suggested questions:
                    </span>
                    {suggestionsToShow.map((q) => (
                      <button
                        key={q}
                        type="button"
                        className="suggestion-pill"
                        disabled={busy}
                        onClick={() => sendMessage(q)}
                      >
                        <span>{q}</span>
                        <ChevronRight size={13} />
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="copilot-messages-list">
                  {messages.map((m) => (
                    <div key={m.id} className={`copilot-msg msg-${m.role}`}>
                      <div className="msg-header">
                        <span className="msg-author">
                          {m.role === "user" ? (
                            "You"
                          ) : (
                            <span className="author-ai">
                              <Sparkles size={12} /> Guardian Intelligence
                            </span>
                          )}
                        </span>
                        <span className="msg-time">
                          {new Date(m.created_at).toLocaleTimeString(
                            undefined,
                            {
                              hour: "2-digit",
                              minute: "2-digit",
                            },
                          )}
                        </span>
                      </div>

                      <div className="msg-bubble">
                        {m.role === "user" ? (
                          <p>{m.content}</p>
                        ) : (
                          <>
                            {renderMarkdown(m.content, onFocusFinding)}

                            {/* Citations section */}
                            {m.citations && m.citations.length > 0 && (
                              <div className="msg-citations-wrap">
                                <span className="citations-header">
                                  Cited Evidence ({m.citations.length})
                                </span>
                                <div className="citations-list">
                                  {m.citations.map((c, i) => (
                                    <div key={i} className="citation-pill">
                                      <button
                                        type="button"
                                        className="citation-name-btn"
                                        onClick={() =>
                                          onFocusFinding?.(c.finding_id)
                                        }
                                        title={`Jump to finding: ${c.title}`}
                                      >
                                        <FileCode2 size={12} />
                                        <span>{c.title}</span>
                                      </button>
                                      {c.text && (
                                        <button
                                          type="button"
                                          className="citation-expand-btn"
                                          onClick={() =>
                                            setExpandedCitations((prev) => ({
                                              ...prev,
                                              [`${m.id}-${i}`]:
                                                !prev[`${m.id}-${i}`],
                                            }))
                                          }
                                        >
                                          {expandedCitations[`${m.id}-${i}`]
                                            ? "Hide"
                                            : "Snippet"}
                                        </button>
                                      )}
                                      {expandedCitations[`${m.id}-${i}`] &&
                                        c.text && (
                                          <pre className="citation-snippet">
                                            <code>{c.text}</code>
                                          </pre>
                                        )}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Limitations */}
                            {m.limitations && m.limitations.length > 0 && (
                              <div className="msg-limitations-box">
                                <Info size={13} />
                                <div>
                                  {m.limitations.map((lim, li) => (
                                    <p key={li}>{lim}</p>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Suggested followups */}
                            {m.suggested_followups &&
                              m.suggested_followups.length > 0 && (
                                <div className="msg-followups">
                                  {m.suggested_followups.map((fQ, fi) => (
                                    <button
                                      key={fi}
                                      type="button"
                                      className="followup-btn"
                                      disabled={busy}
                                      onClick={() => sendMessage(fQ)}
                                    >
                                      {fQ} <ChevronRight size={11} />
                                    </button>
                                  ))}
                                </div>
                              )}
                          </>
                        )}
                      </div>
                    </div>
                  ))}

                  {busy && (
                    <div className="copilot-msg msg-assistant">
                      <div className="msg-header">
                        <span className="author-ai">
                          <Sparkles size={12} /> Guardian Intelligence
                        </span>
                      </div>
                      <div className="msg-bubble busy-bubble">
                        <Loader2 size={16} className="spin text-accent" />
                        <span>
                          Evaluating evidence against report findings…
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Error display */}
            {error && (
              <div className="copilot-error-banner">
                <AlertTriangle size={14} />
                <span>{error}</span>
                <button
                  type="button"
                  onClick={() => setError(null)}
                  className="dismiss-btn"
                >
                  <X size={12} />
                </button>
              </div>
            )}

            {/* Input area */}
            <div className="copilot-footer">
              <form
                className="copilot-input-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  sendMessage(input);
                }}
              >
                <textarea
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      sendMessage(input);
                    }
                  }}
                  placeholder={
                    selectedFinding
                      ? `Ask about "${selectedFinding.title.slice(0, 32)}…" (Enter to send)`
                      : "Ask about findings, dependencies, or risks… (Enter to send)"
                  }
                  rows={2}
                  disabled={busy}
                  className="copilot-textarea"
                />
                <button
                  type="submit"
                  disabled={!input.trim() || busy}
                  className="copilot-send-btn"
                  aria-label="Send message"
                >
                  {busy ? (
                    <Loader2 size={15} className="spin" />
                  ) : (
                    <ArrowUp size={15} />
                  )}
                </button>
              </form>
              <div className="copilot-disclaimer">
                <span>
                  Deterministic facts authoritative · Answers cite scan evidence
                </span>
              </div>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}
