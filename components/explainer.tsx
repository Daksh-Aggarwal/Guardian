"use client";

import { useState, useEffect, useRef } from "react";
import {
  Loader2,
  Shield,
  PlusCircle,
  AlertTriangle,
  Info,
} from "lucide-react";
import {
  Sparkles,
  ArrowUp,
  ChevronRight,
  ShieldCheck,
  RotateCcw,
  CheckCircle2,
  ChevronDown,
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
} from "@/lib/types";

// Lightweight safe markdown renderer for assistant responses
function renderMarkdown(text: string) {
  const lines = text.split("\n");
  const elements: React.ReactNode[] = [];
  let inCodeBlock = false;
  let codeBlockContent: string[] = [];
  let bulletItems: string[] = [];
  let numberedItems: string[] = [];

  function flushLists() {
    if (bulletItems.length > 0) {
      elements.push(
        <ul key={`ul-${elements.length}`}>
          {bulletItems.map((item, idx) => (
            <li key={idx}>{parseInlineMarkdown(item)}</li>
          ))}
        </ul>,
      );
      bulletItems = [];
    }
    if (numberedItems.length > 0) {
      elements.push(
        <ol key={`ol-${elements.length}`}>
          {numberedItems.map((item, idx) => (
            <li key={idx}>{parseInlineMarkdown(item)}</li>
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
          <pre key={`code-${elements.length}`}>
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

    // Numbered list item: e.g. "1. " or "2. "
    const numMatch = trimmed.match(/^(\d+)\.\s+(.*)$/);
    if (numMatch) {
      if (bulletItems.length > 0) flushLists();
      numberedItems.push(numMatch[2]);
      continue;
    }

    // Bullet list item: e.g. "- " or "* "
    if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
      if (numberedItems.length > 0) flushLists();
      bulletItems.push(trimmed.substring(2));
      continue;
    }

    // Any non-list line flushes open lists
    flushLists();

    if (!trimmed) {
      continue;
    }

    // Markdown Headings: #, ##, ###, ####, #####, ######
    if (trimmed.startsWith("###### ")) {
      elements.push(
        <h6 key={`h6-${elements.length}`}>
          {parseInlineMarkdown(trimmed.substring(7))}
        </h6>,
      );
      continue;
    }
    if (trimmed.startsWith("##### ")) {
      elements.push(
        <h5 key={`h5-${elements.length}`}>
          {parseInlineMarkdown(trimmed.substring(6))}
        </h5>,
      );
      continue;
    }
    if (trimmed.startsWith("#### ")) {
      elements.push(
        <h4 key={`h4-${elements.length}`}>
          {parseInlineMarkdown(trimmed.substring(5))}
        </h4>,
      );
      continue;
    }
    if (trimmed.startsWith("### ")) {
      elements.push(
        <h3 key={`h3-${elements.length}`}>
          {parseInlineMarkdown(trimmed.substring(4))}
        </h3>,
      );
      continue;
    }
    if (trimmed.startsWith("## ")) {
      elements.push(
        <h2 key={`h2-${elements.length}`}>
          {parseInlineMarkdown(trimmed.substring(3))}
        </h2>,
      );
      continue;
    }
    if (trimmed.startsWith("# ")) {
      elements.push(
        <h1 key={`h1-${elements.length}`}>
          {parseInlineMarkdown(trimmed.substring(2))}
        </h1>,
      );
      continue;
    }

    // Blockquote
    if (trimmed.startsWith("> ")) {
      elements.push(
        <blockquote key={`quote-${elements.length}`}>
          {parseInlineMarkdown(trimmed.substring(2))}
        </blockquote>,
      );
      continue;
    }

    // Regular paragraph
    elements.push(
      <p key={`p-${elements.length}`}>{parseInlineMarkdown(trimmed)}</p>,
    );
  }

  flushLists();
  if (inCodeBlock && codeBlockContent.length > 0) {
    elements.push(
      <pre key={`code-${elements.length}`}>
        <code>{codeBlockContent.join("\n")}</code>
      </pre>,
    );
  }

  return <div className="markdown-content">{elements}</div>;
}

function parseInlineMarkdown(text: string): React.ReactNode[] {
  // Regex to split tokens: inline code `...`, bold **...**, italic *...*, or markdown links [...](...)
  const parts = text.split(
    /(`[^`]+`|\*\*[^*]+\*\*|(?<!\*)\*[^*]+\*(?!\*)|\[[^\]]+\]\([^)]+\))/g,
  );
  return parts.map((part, index) => {
    if (!part) return null;
    if (part.startsWith("`") && part.endsWith("`") && part.length >= 2) {
      return <code key={index}>{part.slice(1, -1)}</code>;
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
      return (
        <a
          key={index}
          href={linkMatch[2]}
          target="_blank"
          rel="noopener noreferrer"
          className="text-link"
        >
          {linkMatch[1]}
        </a>
      );
    }
    return part;
  });
}

export default function Explainer({
  report,
  onFinding,
  advanced = false,
}: {
  report: Report;
  onFinding: (id: string) => void;
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

  // Initialize consent from localStorage and fetch AI status
  useEffect(() => {
    try {
      const stored = localStorage.getItem("guardian_ai_consent");
      if (stored === "true") {
        setConsent(true);
      }
    } catch {}

    api<AIStatus>("/ai/status")
      .then((status) => setAiStatus(status))
      .catch(() => {});
  }, []);

  // Fetch or create conversation on report load
  useEffect(() => {
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

  // Scroll only the internal conversation-feed container when messages update (never scroll window/page)
  useEffect(() => {
    if (feedRef.current && messages.length > 0) {
      feedRef.current.scrollTo({
        top: feedRef.current.scrollHeight,
        behavior: "smooth",
      });
    }
  }, [messages.length, busy]);

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

    // Optimistic temporary user message
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
      const response = await api<AdvisorResponse>(
        `/scans/${report.id}/conversation/message`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            question: q,
            consent: consent,
            conversation_id: conversationId,
            mode: advanced ? "advanced" : "simple",
          }),
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
      // Roll back optimistic message on failure
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

  // Dynamic suggested prompts derived from current report findings
  const highFinding = report.findings.find((f) =>
    ["high", "critical"].includes(f.severity),
  );
  const hasAdvisories = report.findings.some(
    (f) => f.rule === "OSV" || f.advisory,
  );
  const dataFlowFinding = report.findings.find(
    (f) => f.data_flows && f.data_flows.length > 0,
  );

  const dynamicSuggestions: string[] = [];
  if (highFinding) {
    dynamicSuggestions.push(`Why is "${highFinding.title}" dangerous?`);
  }
  if (hasAdvisories) {
    dynamicSuggestions.push(
      `Does the advisory apply to our version ${report.version}?`,
    );
  }
  if (dataFlowFinding) {
    dynamicSuggestions.push("Explain the sensitive data-flow path");
  }
  dynamicSuggestions.push("What practical steps should we take first?");
  dynamicSuggestions.push("Is this package safe to use in production?");

  const suggestionsToShow = dynamicSuggestions.slice(0, 3);
  const activeProvider =
    aiStatus?.enabled && consent ? "gemini" : "deterministic";
  const activeModel = aiStatus?.model || "gemini-3.8-flash";

  return (
    <section className="card explainer">
      {/* Header */}
      <div className="assistant-header">
        <div className="inline">
          <span className="spark-icon">
            <Sparkles size={19} />
          </span>
          <div>
            <h3 style={{ margin: 0, fontSize: "14px", fontWeight: 600 }}>
              Guardian Intelligence
            </h3>
            <p style={{ margin: 0, fontSize: "11px", color: "var(--muted)" }}>
              Contextual security advisor grounded in verified findings.
            </p>
          </div>
        </div>

        <div className="assistant-badges">
          <span className={`intelligence-badge ${activeProvider}`}>
            <span
              className={`status-dot ${activeProvider === "gemini" ? "pulse-dot" : ""}`}
            />
            {activeProvider === "gemini" ? activeModel : "Deterministic Engine"}
          </span>

          <button
            type="button"
            className="ghost-btn"
            onClick={() => setShowPrivacyBanner((prev) => !prev)}
            title="Inspect privacy boundary and AI consent"
          >
            {consent ? (
              <ShieldCheck size={13} color="#409379" />
            ) : (
              <Shield size={13} />
            )}
            {consent ? "AI Enabled" : "Privacy / Local"}
          </button>

          {messages.length > 0 && (
            <>
              <button
                type="button"
                className="ghost-btn"
                onClick={handleNewConversation}
                disabled={busy}
                title="Start a new conversation"
              >
                <PlusCircle size={13} />
                New
              </button>
              <button
                type="button"
                className="ghost-btn"
                onClick={handleClearConversation}
                disabled={busy}
                title="Clear conversation history"
              >
                <RotateCcw size={13} />
                Clear
              </button>
            </>
          )}
        </div>
      </div>

      {/* Privacy Consent Disclosure Drawer */}
      <AnimatePresence>
        {showPrivacyBanner && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="privacy-banner"
          >
            <h4>
              <Shield size={14} /> Privacy-First Intelligence Boundary
            </h4>
            <p style={{ color: "var(--muted)", margin: "4px 0" }}>
              Guardian uses local-first static analysis. When AI is enabled,
              contextual findings are analyzed using Google Gemini:
            </p>
            <ul>
              <li>
                Package identifiers, assessment summaries, and finding IDs are
                included.
              </li>
              <li>
                Relevant code snippets are redacted for API keys, tokens, and
                private secrets.
              </li>
              <li>
                Uploaded project archives and complete source trees are{" "}
                <strong>never</strong> transmitted.
              </li>
              <li>
                Local deterministic explanations remain fully available without
                cloud inference.
              </li>
            </ul>

            <label className="privacy-consent-toggle">
              <input
                type="checkbox"
                checked={consent}
                onChange={(e) => handleConsentChange(e.target.checked)}
              />
              <span>
                I consent to sending selected report findings to Google Gemini (
                {activeModel})
              </span>
            </label>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Suggested prompts on empty chat */}
      {messages.length === 0 && (
        <div className="suggestions">
          {suggestionsToShow.map((q) => (
            <button
              type="button"
              key={q}
              disabled={busy}
              onClick={() => sendMessage(q)}
            >
              {q}
              <ChevronRight size={13} />
            </button>
          ))}
        </div>
      )}

      {/* Conversation Thread */}
      {messages.length > 0 && (
        <div className="conversation-feed" ref={feedRef} aria-live="polite">
          {messages.map((msg, index) => (
            <motion.div
              key={msg.id || index}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className={`msg-row ${msg.role}`}
            >
              <div className="msg-meta">
                <span>
                  {msg.role === "user" ? "You" : "Guardian Intelligence"}
                </span>
                {msg.role === "assistant" && (
                  <span style={{ opacity: 0.7 }}>
                    ·{" "}
                    {msg.provider === "gemini"
                      ? msg.model || "Gemini"
                      : "Deterministic"}
                  </span>
                )}
              </div>

              <div className={`msg-bubble ${msg.role}`}>
                {msg.role === "user" ? (
                  <p style={{ margin: 0 }}>{msg.content}</p>
                ) : (
                  <>
                    {renderMarkdown(msg.content)}

                    {/* Grounded Citations */}
                    {msg.citations && msg.citations.length > 0 && (
                      <div className="citations-group">
                        <span>Report Evidence Citations:</span>
                        <div className="citation-chips">
                          {msg.citations.map((c, ci) => {
                            const isExpanded =
                              expandedCitations[`${msg.id}-${ci}`];
                            return (
                              <div
                                key={ci}
                                style={{
                                  display: "flex",
                                  flexDirection: "column",
                                }}
                              >
                                <button
                                  type="button"
                                  className="citation-chip"
                                  onClick={() => onFinding(c.finding_id)}
                                  title="Click to locate finding in report"
                                >
                                  <CheckCircle2 size={12} color="#409379" />
                                  <span>{c.title}</span>
                                  <ChevronRight size={12} />
                                </button>
                                {c.text && (
                                  <div
                                    className="citation-text"
                                    onClick={() =>
                                      setExpandedCitations((prev) => ({
                                        ...prev,
                                        [`${msg.id}-${ci}`]: !isExpanded,
                                      }))
                                    }
                                  >
                                    {isExpanded
                                      ? c.text
                                      : c.text.slice(0, 120) +
                                        (c.text.length > 120 ? "..." : "")}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Uncertainty & Limitations */}
                    {msg.limitations && msg.limitations.length > 0 && (
                      <div className="limitations-box">
                        <strong>Analysis Uncertainty:</strong>{" "}
                        {msg.limitations.join(" ")}
                      </div>
                    )}

                    {/* Contextual Follow-Up Suggestions */}
                    {msg.suggested_followups &&
                      msg.suggested_followups.length > 0 &&
                      index === messages.length - 1 &&
                      !busy && (
                        <div className="followups-group">
                          {msg.suggested_followups.map((fQ, fi) => (
                            <button
                              key={fi}
                              type="button"
                              className="followup-btn"
                              onClick={() => sendMessage(fQ)}
                            >
                              <span>{fQ}</span>
                              <ChevronRight size={11} />
                            </button>
                          ))}
                        </div>
                      )}
                  </>
                )}
              </div>
            </motion.div>
          ))}

          {busy && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="msg-row assistant"
            >
              <div className="msg-meta">
                <span>Guardian Intelligence is reasoning...</span>
              </div>
              <div className="msg-bubble assistant">
                <div className="typing-dots">
                  <span />
                  <span />
                  <span />
                </div>
              </div>
            </motion.div>
          )}
        </div>
      )}

      {/* Multiline Input Box */}
      <form
        className="multiline-input-wrapper"
        onSubmit={(e) => {
          e.preventDefault();
          sendMessage(input);
        }}
      >
        <textarea
          aria-label="Ask Guardian Intelligence about this report"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              sendMessage(input);
            }
          }}
          placeholder="Ask a question about this report (Enter to send, Shift+Enter for newline)..."
          maxLength={1000}
          className="multiline-textarea"
          rows={2}
          disabled={busy}
        />
        <div className="multiline-input-footer">
          <span className="char-count">{input.length}/1000</span>
          <button
            type="submit"
            className="send-btn"
            disabled={busy || !input.trim()}
            aria-label="Send message"
          >
            {busy ? (
              <Loader2 className="spin" size={14} />
            ) : (
              <>
                <span>Send</span>
                <ArrowUp size={13} />
              </>
            )}
          </button>
        </div>
      </form>

      {/* Error state */}
      {error && (
        <div
          style={{
            marginTop: "10px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
            color: "#bb624d",
            fontSize: "11px",
          }}
          role="alert"
        >
          <AlertTriangle size={15} />
          <span>{error}</span>
        </div>
      )}

      <small
        style={{
          display: "block",
          fontSize: "9px",
          color: "var(--muted)",
          marginTop: "10px",
        }}
      >
        Evidence-grounded explanations ·{" "}
        {activeProvider === "gemini"
          ? `Google Gemini (${activeModel})`
          : "Deterministic Engine"}{" "}
        · All claims cited to stored report findings
      </small>
    </section>
  );
}
