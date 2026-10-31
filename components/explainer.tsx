"use client";
import { useState } from "react";
import { Sparkles, ArrowUp, Loader2, ChevronRight } from "lucide-react";
import { api, Answer, Report } from "@/lib/types";
export default function Explainer({
  report,
  onFinding,
}: {
  report: Report;
  onFinding: (id: string) => void;
}) {
  const [question, setQuestion] = useState(""),
    [answer, setAnswer] = useState<Answer | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  async function ask(q: string) {
    if (!q.trim()) return;
    setBusy(true);
    setError("");
    try {
      setAnswer(
        await api(`/scans/${report.id}/explain`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ question: q }),
        }),
      );
      setQuestion("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="card explainer">
      <div className="section-heading">
        <div className="inline">
          <span className="spark-icon">
            <Sparkles size={19} />
          </span>
          <div>
            <h3>A little more clarity.</h3>
            <p>Ask about the evidence in this report.</p>
          </div>
        </div>
        <span className="small-label">GROUNDED EXPLANATIONS</span>
      </div>
      <div className="suggestions">
        {[
          "Can I trust this package?",
          "What should I do next?",
          "Explain the highest risk",
        ].map((q) => (
          <button key={q} disabled={busy} onClick={() => ask(q)}>
            {q}
            <ChevronRight size={13} />
          </button>
        ))}
      </div>
      {answer && (
        <div className="answer" aria-live="polite">
          <p>{answer.answer}</p>
          {answer.citations.map((c) => (
            <div key={c.finding_id}>
              <button
                className="text-link"
                onClick={() => onFinding(c.finding_id)}
              >
                {c.title}
                <ChevronRight size={14} />
              </button>
              <p>{c.text}</p>
            </div>
          ))}
        </div>
      )}
      <form
        className="ask-input"
        onSubmit={(e) => {
          e.preventDefault();
          ask(question);
        }}
      >
        <input
          aria-label="Ask about this report"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="What does this mean for my project?"
          maxLength={1000}
        />
        <button aria-label="Send question" disabled={busy || !question.trim()}>
          {busy ? (
            <Loader2 className="spin" size={17} />
          ) : (
            <ArrowUp size={17} />
          )}
        </button>
      </form>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <small>
        Evidence-based answers · Deterministic provider · No external AI service
      </small>
    </section>
  );
}
