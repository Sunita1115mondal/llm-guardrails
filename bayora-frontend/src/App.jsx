
import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Clipboard,
  Clock3,
  Command,
  FileCheck2,
  Fingerprint,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  RefreshCw,
  RotateCw,
  ScanSearch,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Users,
  X,
} from "lucide-react";
import "./App.css";

const API = "http://127.0.0.1:8000";

const NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "simulator", label: "Attack simulator", icon: ScanSearch },
  { id: "teams", label: "Team isolation", icon: Users },
  { id: "audit", label: "Audit integrity", icon: FileCheck2 },
];

const LAYOUTS = [
  "sidebar-left",
  "sidebar-right",
  "top-nav",
  "two-column",
  "card-grid",
  "centered",
];

const DEFAULT_METRICS = [
  {
    label: "Guardrail status",
    value: "Active",
    detail: "Protection enabled",
    icon: ShieldCheck,
    tone: "sage",
  },
  {
    label: "API connection",
    value: "Checking",
    detail: "Connecting to backend",
    icon: Activity,
    tone: "sand",
  },
  {
    label: "Security events",
    value: "0",
    detail: "Recent session activity",
    icon: Fingerprint,
    tone: "clay",
  },
  {
    label: "Audit integrity",
    value: "Ready",
    detail: "Verification available",
    icon: FileCheck2,
    tone: "blue",
  },
];

function makeSeed() {
  return Math.floor(Math.random() * 900000) + 100000;
}

function shuffleArray(items, seed) {
  const result = [...items];
  let state = seed || 1;

  const random = () => {
    state = (state * 16807) % 2147483647;
    return (state - 1) / 2147483646;
  };

  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }

  return result;
}

function createLayout(seed, previousTemplate) {
  const available = LAYOUTS.filter(
    (item) => item !== previousTemplate,
  );

  const template = available[seed % available.length];

  return {
    seed,
    template,
    order: shuffleArray(
      ["welcome", "metrics", "quick-test", "activity", "security-note"],
      seed,
    ),
  };
}

function prettyJson(value) {
  if (typeof value === "string") return value;

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value ?? "");
  }
}

function getErrorMessage(error) {
  return error instanceof Error
    ? error.message
    : String(error);
}

/**
 * Parse JSON responses and include the HTTP status in errors.
 */
async function readResponse(response) {
  const raw = await response.text();

  let data;

  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    data = { detail: raw };
  }

  if (!response.ok) {
    console.error("Bayora API error:", {
      status: response.status,
      responseBody: data,
    });

    const detail =
      typeof data?.detail === "string"
        ? data.detail
        : data?.detail
          ? prettyJson(data.detail)
          : data?.error || response.statusText;

    throw new Error(
      `HTTP ${response.status}: ${detail || "Request failed."}`,
    );
  }

  return data;
}

/**
 * Accept either a raw token or a token already prefixed with Bearer.
 */
function makeAuthorizationHeader(token) {
  const value = token.trim();

  if (!value) return null;

  return /^Bearer\s+/i.test(value)
    ? value
    : `Bearer ${value}`;
}

function getMessage(data, fallback = "Request completed.") {
  if (typeof data === "string") return data;

  const message =
    data?.message ??
    data?.detail ??
    data?.status ??
    data?.result;

  return typeof message === "string"
    ? message
    : message != null
      ? prettyJson(message)
      : fallback;
}

function StatusPill({ status, children }) {
  return (
    <span className={`status-pill ${status || "neutral"}`}>
      <span className="status-dot" />
      {children}
    </span>
  );
}

function SectionHeading({
  eyebrow,
  title,
  description,
  action,
}) {
  return (
    <div className="section-heading">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h2>{title}</h2>
        {description && (
          <p className="section-description">{description}</p>
        )}
      </div>

      {action && <div className="heading-action">{action}</div>}
    </div>
  );
}

function MetricCard({ metric, index }) {
  const Icon = metric.icon;

  return (
    <article
      className={`metric-card metric-${metric.tone}`}
      style={{ "--stagger": `${index * 65}ms` }}
    >
      <div className="metric-top">
        <span className="metric-icon">
          <Icon size={19} strokeWidth={1.8} />
        </span>
        <ArrowUpRight className="metric-arrow" size={17} />
      </div>

      <p className="metric-label">{metric.label}</p>
      <h3>{metric.value}</h3>
      <p className="metric-detail">{metric.detail}</p>
    </article>
  );
}

function EmptyState({
  icon: Icon = Activity,
  title,
  detail,
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Icon size={22} />
      </span>
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}

function ResultPanel({
  title,
  result,
  emptyIcon: EmptyIcon,
  emptyTitle,
  emptyDetail,
  onCopy,
}) {
  return (
    <section className="surface-card">
      <div className="card-heading">
        <div className="card-heading-icon clay-icon">
          <Terminal size={19} />
        </div>

        <div>
          <h3>{title}</h3>
          <p>Latest response returned by your backend.</p>
        </div>

        {result != null && (
          <button
            type="button"
            className="icon-button"
            onClick={() => onCopy(prettyJson(result))}
            aria-label={`Copy ${title}`}
          >
            <Clipboard size={16} />
          </button>
        )}
      </div>

      {result != null ? (
        <pre className="code-output">
          {prettyJson(result)}
        </pre>
      ) : (
        <EmptyState
          icon={EmptyIcon}
          title={emptyTitle}
          detail={emptyDetail}
        />
      )}
    </section>
  );
}

function App() {
  const [page, setPage] = useState("overview");
  const [apiStatus, setApiStatus] = useState("checking");
  const [healthData, setHealthData] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState(null);

  const [layout, setLayout] = useState(() =>
    createLayout(makeSeed()),
  );
  const [shuffleKey, setShuffleKey] = useState(0);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  // Attack simulator state
  const [prompt, setPrompt] = useState("");
  const [simulatorResult, setSimulatorResult] = useState(null);

  // Team isolation state
  const [team, setTeam] = useState("red");
  const [teamToken, setTeamToken] = useState("");
  const [teamResult, setTeamResult] = useState(null);

  // Audit state: separate input and output
  const [auditRequestPayload, setAuditRequestPayload] = useState("{}");
  const [auditResult, setAuditResult] = useState(null);

  const showNotice = useCallback((type, message) => {
    setNotice({ type, message });
  }, []);

  const addEvent = useCallback((title, detail, type = "success") => {
    setEvents((current) =>
      [
        {
          id: `${Date.now()}-${Math.random()}`,
          title,
          detail,
          time: new Date().toLocaleTimeString(),
          type,
        },
        ...current,
      ].slice(0, 8),
    );
  }, []);

  const checkHealth = useCallback(async () => {
    try {
      const response = await fetch(`${API}/health`);
      const data = await readResponse(response);

      setHealthData(data);
      setApiStatus("connected");
    } catch (error) {
      setApiStatus("offline");
      setHealthData(null);
      console.error("Health check failed:", error);
    }
  }, []);

  const loadReadiness = useCallback(async () => {
    try {
      const response = await fetch(`${API}/ready`);
      const data = await readResponse(response);

      setHealthData((current) => ({
        ...(current || {}),
        readiness: data,
      }));
    } catch (error) {
      console.warn("Readiness check unavailable:", error);
    }
  }, []);

  useEffect(() => {
    checkHealth();
    loadReadiness();

    const interval = window.setInterval(checkHealth, 15000);

    return () => window.clearInterval(interval);
  }, [checkHealth, loadReadiness]);

  const shuffleLayout = () => {
    const seed = makeSeed();

    setLayout((current) =>
      createLayout(seed, current.template),
    );
    setShuffleKey((current) => current + 1);
  };

  const copyText = async (value) => {
    try {
      await navigator.clipboard.writeText(value);
      showNotice("success", "Copied to clipboard.");
    } catch {
      showNotice(
        "warning",
        "Clipboard access is unavailable in this browser.",
      );
    }
  };

  // ------------------------------------
  // Attack simulator: POST /guard/input
  // ------------------------------------
  const runGuardrail = async (event) => {
    event?.preventDefault();

    const cleanPrompt = prompt.trim();

    if (!cleanPrompt) {
      showNotice(
        "warning",
        "Enter a prompt before running the security test.",
      );
      return;
    }

    setLoading(true);
    setSimulatorResult(null);

    try {
      const response = await fetch(`${API}/guard/input`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          text: cleanPrompt,
        }),
      });

      const data = await readResponse(response);

      setSimulatorResult(data);

      addEvent(
        "Prompt evaluation completed",
        getMessage(data, "Input guardrail returned a response."),
      );

      showNotice("success", "Input guardrail evaluation completed.");
    } catch (error) {
      const message = getErrorMessage(error);

      setSimulatorResult({ error: message });
      addEvent("Prompt evaluation failed", message, "error");
      showNotice("error", message);
    } finally {
      setLoading(false);
    }
  };

  // ------------------------------------
  // Team isolation: GET /bayora/private/{team}
  // ------------------------------------
  const accessTeamData = async (event) => {
    event?.preventDefault();

    const cleanTeam = team.trim();

    if (!cleanTeam) {
      showNotice("warning", "Enter a team identifier.");
      return;
    }

    setLoading(true);
    setTeamResult(null);

    try {
      const headers = {
        Accept: "application/json",
      };

      const authorization = makeAuthorizationHeader(teamToken);

      if (authorization) {
        headers.Authorization = authorization;
      }

      // This endpoint is GET according to your FastAPI /docs.
      // GET requests should not include a JSON request body.
      const response = await fetch(
        `${API}/bayora/private/${encodeURIComponent(cleanTeam)}`,
        {
          method: "GET",
          headers,
        },
      );

      const data = await readResponse(response);

      setTeamResult({
        success: true,
        status: response.status,
        team: cleanTeam,
        data,
      });

      addEvent(
        "Team access request completed",
        `Team "${cleanTeam}" returned HTTP ${response.status}.`,
      );

      showNotice(
        "success",
        `Team "${cleanTeam}" request completed.`,
      );
    } catch (error) {
      const message = getErrorMessage(error);
      const statusMatch = message.match(/HTTP (\d{3})/);

      setTeamResult({
        success: false,
        team: cleanTeam,
        status: statusMatch ? Number(statusMatch[1]) : null,
        error: message,
      });

      addEvent(
        "Team access request failed",
        message,
        "error",
      );

      showNotice("error", message);
    } finally {
      setLoading(false);
    }
  };

  // ------------------------------------
  // Audit integrity: POST /bayora/audit/verify
  // ------------------------------------
  const verifyAudit = async (event) => {
    event?.preventDefault();

    let body;

    try {
      body = auditRequestPayload.trim()
        ? JSON.parse(auditRequestPayload)
        : {};
    } catch {
      showNotice(
        "warning",
        "Audit payload must contain valid JSON.",
      );
      return;
    }

    setLoading(true);
    setAuditResult(null);

    try {
      const response = await fetch(`${API}/bayora/audit/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
      });

      const data = await readResponse(response);

      setAuditResult({
        success: true,
        status: response.status,
        data,
      });

      addEvent(
        "Audit verification completed",
        `Audit endpoint returned HTTP ${response.status}.`,
      );

      showNotice("success", "Audit verification request completed.");
    } catch (error) {
      const message = getErrorMessage(error);
      const statusMatch = message.match(/HTTP (\d{3})/);

      setAuditResult({
        success: false,
        status: statusMatch ? Number(statusMatch[1]) : null,
        error: message,
      });

      addEvent("Audit verification failed", message, "error");
      showNotice("error", message);
    } finally {
      setLoading(false);
    }
  };

  const metrics = DEFAULT_METRICS.map((metric) => {
    if (metric.label === "API connection") {
      return {
        ...metric,
        value:
          apiStatus === "connected"
            ? "Connected"
            : apiStatus === "offline"
              ? "Offline"
              : "Checking",
        detail:
          apiStatus === "connected"
            ? "Backend responding"
            : apiStatus === "offline"
              ? "Check the FastAPI server"
              : "Checking backend health",
      };
    }

    if (metric.label === "Security events") {
      return {
        ...metric,
        value: String(events.length),
        detail: "Recent activity in this session",
      };
    }

    return metric;
  });

  const pageTitle =
    NAV_ITEMS.find((item) => item.id === page)?.label || "Overview";

  const isHorizontalNav = layout.template === "top-nav";

  // ------------------------------------
  // Overview sections
  // ------------------------------------
  const renderWelcome = () => (
    <section className="welcome-card" key="welcome">
      <div className="welcome-copy">
        <span className="welcome-tag">
          <Sparkles size={14} /> SECURITY WORKSPACE
        </span>

        <h2>
          Trust, <em>tested.</em>
        </h2>

        <p>
          A thoughtful workspace for testing AI guardrails,
          reviewing adversarial inputs, and validating your
          safety infrastructure.
        </p>

        <div className="welcome-actions">
          <button
            className="button button-primary"
            onClick={() => setPage("simulator")}
          >
            Run a security test <ArrowRight size={16} />
          </button>

          <button
            className="button button-secondary"
            onClick={() => setPage("audit")}
          >
            Verify audit trail
          </button>
        </div>
      </div>

      <div className="welcome-art" aria-hidden="true">
        <div className="orbit orbit-one" />
        <div className="orbit orbit-two" />
        <div className="orbit orbit-three" />

        <div className="shield-orb">
          <ShieldCheck size={50} strokeWidth={1.3} />
        </div>

        <span className="art-spark art-spark-one">✳</span>
        <span className="art-spark art-spark-two">✦</span>
      </div>
    </section>
  );

  const renderMetrics = () => (
    <section className="metrics-grid" key="metrics">
      {metrics.map((metric, index) => (
        <MetricCard
          key={metric.label}
          metric={metric}
          index={index}
        />
      ))}
    </section>
  );

  const renderQuickTest = () => (
    <section
      className="surface-card quick-test-card"
      key="quick-test"
    >
      <div className="card-heading">
        <div className="card-heading-icon sage-icon">
          <Terminal size={19} />
        </div>

        <div>
          <h3>Quick security test</h3>
          <p>Check a prompt against your input guardrails.</p>
        </div>

        <span className="mini-label">INPUT</span>
      </div>

      <form onSubmit={runGuardrail} className="quick-test-form">
        <label className="field-label" htmlFor="quick-prompt">
          Test prompt
        </label>

        <textarea
          id="quick-prompt"
          value={prompt}
          onChange={(event) => setPrompt(event.target.value)}
          placeholder="Paste a prompt you want to evaluate…"
          rows={4}
        />

        <div className="form-footer">
          <span className="helper-text">
            Evaluated by your running Bayora API.
          </span>

          <button
            className="button button-primary"
            type="submit"
            disabled={loading}
          >
            {loading ? (
              <RefreshCw className="spin-icon" size={15} />
            ) : (
              <ScanSearch size={16} />
            )}
            {loading ? "Testing…" : "Evaluate prompt"}
          </button>
        </div>
      </form>

      {simulatorResult != null && (
        <div className="result-panel">
          <div className="result-panel-heading">
            <strong>Evaluation response</strong>

            <button
              type="button"
              className="icon-button"
              onClick={() => copyText(prettyJson(simulatorResult))}
              aria-label="Copy evaluation"
            >
              <Clipboard size={15} />
            </button>
          </div>

          <pre>{prettyJson(simulatorResult)}</pre>
        </div>
      )}
    </section>
  );

  const renderActivity = () => (
    <section className="surface-card activity-card" key="activity">
      <div className="card-heading">
        <div className="card-heading-icon clay-icon">
          <Activity size={19} />
        </div>

        <div>
          <h3>Recent activity</h3>
          <p>Events from your current session.</p>
        </div>

        <button
          className="text-button"
          onClick={() => setEvents([])}
        >
          Clear
        </button>
      </div>

      {events.length ? (
        <div className="activity-list">
          {events.map((item) => (
            <div className="activity-row" key={item.id}>
              <span
                className={`activity-indicator ${item.type || "neutral"}`}
              >
                {item.type === "error" ? (
                  <CircleAlert size={14} />
                ) : (
                  <Check size={14} />
                )}
              </span>

              <div className="activity-copy">
                <strong>{item.title}</strong>
                <p>{item.detail}</p>
              </div>

              <time>{item.time}</time>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState
          icon={Clock3}
          title="A little quiet here"
          detail="Run a security test to see your latest activity appear here."
        />
      )}
    </section>
  );

  const renderSecurityNote = () => (
    <section className="security-note" key="security-note">
      <div className="note-icon">
        <LockKeyhole size={20} />
      </div>

      <div>
        <h3>Security is a practice, not a checkbox.</h3>
        <p>
          Test your guardrails with realistic inputs and verify
          your audit trail regularly.
        </p>
      </div>

      <ArrowUpRight size={18} className="note-arrow" />
    </section>
  );

  const blockRenderers = {
    welcome: renderWelcome,
    metrics: renderMetrics,
    "quick-test": renderQuickTest,
    activity: renderActivity,
    "security-note": renderSecurityNote,
  };

  const renderOverview = () => (
    <div
      key={shuffleKey}
      className={`overview-layout template-${layout.template} layout-shuffling`}
    >
      {layout.order.map((block) => (
        <div
          className={`overview-block block-${block}`}
          key={`${layout.seed}-${block}`}
        >
          {blockRenderers[block]?.()}
        </div>
      ))}
    </div>
  );

  // ------------------------------------
  // Attack simulator page
  // ------------------------------------
  const renderSimulator = () => (
    <div className="page-stack">
      <SectionHeading
        eyebrow="ADVERSARIAL TESTING"
        title="Attack simulator"
        description="Send a prompt to your input guardrail and inspect the response."
        action={
          <StatusPill status={apiStatus}>
            {apiStatus === "connected"
              ? "API connected"
              : apiStatus}
          </StatusPill>
        }
      />

      <section className="surface-card">
        <div className="card-heading">
          <div className="card-heading-icon sage-icon">
            <ScanSearch size={19} />
          </div>

          <div>
            <h3>Prompt evaluation</h3>
            <p>Submit a test case to the backend input guard.</p>
          </div>
        </div>

        <form onSubmit={runGuardrail} className="stack-form">
          <label
            className="field-label"
            htmlFor="simulator-prompt"
          >
            Adversarial prompt
          </label>

          <textarea
            id="simulator-prompt"
            rows={7}
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            placeholder="Enter a prompt to test your safety controls…"
          />

          <div className="form-footer">
            <span className="helper-text">
              Endpoint: POST /guard/input
            </span>

            <button
              className="button button-primary"
              type="submit"
              disabled={loading}
            >
              {loading ? (
                <RefreshCw className="spin-icon" size={15} />
              ) : (
                <Shield size={16} />
              )}
              {loading ? "Evaluating…" : "Run evaluation"}
            </button>
          </div>
        </form>
      </section>

      <ResultPanel
        title="Response details"
        result={simulatorResult}
        emptyIcon={ScanSearch}
        emptyTitle="No evaluation yet"
        emptyDetail="Run a prompt evaluation to inspect the result here."
        onCopy={copyText}
      />
    </div>
  );

  // ------------------------------------
  // Team isolation page
  // ------------------------------------
  const renderTeams = () => (
    <div className="page-stack">
      <SectionHeading
        eyebrow="ACCESS CONTROL"
        title="Team isolation"
        description="Test access to a team-specific private endpoint."
      />

      <div className="info-banner">
        <LockKeyhole size={19} />
        <p>
          The API validates Bearer credentials and decides whether
          the requested team can be accessed. A missing or invalid
          token should not be treated as successful authorization.
        </p>
      </div>

      <section className="surface-card">
        <div className="card-heading">
          <div className="card-heading-icon sage-icon">
            <Users size={19} />
          </div>

          <div>
            <h3>Private team request</h3>
            <p>Configure the team and its access credentials.</p>
          </div>
        </div>

        <form onSubmit={accessTeamData} className="stack-form">
          <label className="field-label" htmlFor="team-name">
            Team identifier
          </label>

          <input
            id="team-name"
            value={team}
            onChange={(event) => setTeam(event.target.value)}
            placeholder="red"
            autoComplete="off"
            required
          />

          <label className="field-label" htmlFor="team-token">
            Bearer access token{" "}
            <span className="optional-label">Optional if public</span>
          </label>

          <input
            id="team-token"
            type="password"
            value={teamToken}
            onChange={(event) => setTeamToken(event.target.value)}
            placeholder="Enter a valid token issued or accepted by your API"
            autoComplete="off"
          />

          <p className="helper-text">
            Enter the token only if you have one. The endpoint
            documentation indicates that valid Bearer credentials
            are required.
          </p>

          <div className="form-footer">
            <span className="helper-text">
              GET /bayora/private/{team || "{team}"}
            </span>

            <button
              className="button button-primary"
              type="submit"
              disabled={loading}
            >
              {loading ? (
                <RefreshCw className="spin-icon" size={15} />
              ) : (
                <LockKeyhole size={16} />
              )}
              {loading ? "Checking…" : "Test team access"}
            </button>
          </div>
        </form>
      </section>

      <ResultPanel
        title="Team access response"
        result={teamResult}
        emptyIcon={Users}
        emptyTitle="Waiting for a request"
        emptyDetail="The response and HTTP status will appear here after you test team access."
        onCopy={copyText}
      />
    </div>
  );

  // ------------------------------------
  // Audit integrity page
  // ------------------------------------
  const renderAudit = () => (
    <div className="page-stack">
      <SectionHeading
        eyebrow="INTEGRITY & TRACEABILITY"
        title="Audit integrity"
        description="Ask the backend to verify its audit trail and inspect the result."
      />

      <div className="audit-intro">
        <div className="audit-intro-icon">
          <Fingerprint size={28} />
        </div>

        <div>
          <h3>Verify what happened.</h3>
          <p>
            Audit verification can help identify inconsistencies
            in recorded events. A successful verification response
            does not, by itself, guarantee that a system is tamper-proof.
          </p>
        </div>
      </div>

      <section className="surface-card">
        <div className="card-heading">
          <div className="card-heading-icon sage-icon">
            <FileCheck2 size={19} />
          </div>

          <div>
            <h3>Verify audit trail</h3>
            <p>Send a verification request to Bayora.</p>
          </div>
        </div>

        <form onSubmit={verifyAudit} className="stack-form">
          <label
            className="field-label"
            htmlFor="audit-request-payload"
          >
            Verification payload (JSON)
          </label>

          <textarea
            id="audit-request-payload"
            rows={5}
            value={auditRequestPayload}
            onChange={(event) =>
              setAuditRequestPayload(event.target.value)
            }
            placeholder="{}"
            spellCheck={false}
          />

          <div className="form-footer">
            <span className="helper-text">
              POST /bayora/audit/verify
            </span>

            <button
              className="button button-primary"
              type="submit"
              disabled={loading}
            >
              {loading ? (
                <RefreshCw className="spin-icon" size={15} />
              ) : (
                <ShieldCheck size={16} />
              )}
              {loading ? "Verifying…" : "Verify integrity"}
            </button>
          </div>
        </form>
      </section>

      <ResultPanel
        title="Verification result"
        result={auditResult}
        emptyIcon={FileCheck2}
        emptyTitle="No verification run yet"
        emptyDetail="Run an audit verification to view the backend result."
        onCopy={copyText}
      />
    </div>
  );

  const renderPage = () => {
    if (page === "simulator") return renderSimulator();
    if (page === "teams") return renderTeams();
    if (page === "audit") return renderAudit();

    return renderOverview();
  };

  // ------------------------------------
  // Application shell
  // ------------------------------------
  return (
    <div
      className={`app-shell template-shell-${layout.template} ${
        isHorizontalNav ? "horizontal-nav" : ""
      }`}
    >
      {mobileNavOpen && (
        <button
          className="mobile-backdrop"
          aria-label="Close navigation"
          onClick={() => setMobileNavOpen(false)}
        />
      )}

      {!isHorizontalNav && (
        <aside
          className={`sidebar ${
            layout.template === "sidebar-right"
              ? "sidebar-right"
              : ""
          } ${mobileNavOpen ? "sidebar-open" : ""}`}
        >
          <a
            href="#overview"
            className="brand"
            onClick={(event) => {
              event.preventDefault();
              setPage("overview");
              setMobileNavOpen(false);
            }}
          >
            <span className="brand-mark">
              <ShieldCheck size={23} strokeWidth={1.8} />
            </span>

            <span className="brand-copy">
              <strong>
                bayora<span>.</span>
              </strong>
              <small>AI SAFETY PLATFORM</small>
            </span>
          </a>

          <div className="workspace-label">WORKSPACE</div>

          <nav className="sidebar-nav" aria-label="Main navigation">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;

              return (
                <button
                  key={item.id}
                  className={`nav-item ${
                    page === item.id ? "active" : ""
                  }`}
                  onClick={() => {
                    setPage(item.id);
                    setMobileNavOpen(false);
                  }}
                >
                  <Icon size={18} strokeWidth={1.8} />
                  <span>{item.label}</span>

                  {page === item.id && (
                    <ChevronRight
                      className="nav-chevron"
                      size={15}
                    />
                  )}
                </button>
              );
            })}
          </nav>

          <div className="sidebar-spacer" />

          <div className="sidebar-status-card">
            <div className="sidebar-status-top">
              <span className="tiny-status-dot" />
              <span>Backend status</span>
            </div>

            <strong>
              {apiStatus === "connected"
                ? "All systems connected"
                : apiStatus === "offline"
                  ? "Connection unavailable"
                  : "Checking connection"}
            </strong>

            <p>
              {apiStatus === "connected"
                ? "Your API is responding."
                : "Check that the FastAPI server is running."}
            </p>

            <button
              className="sidebar-refresh"
              onClick={checkHealth}
            >
              <RotateCw size={14} /> Refresh connection
            </button>
          </div>

          <div className="sidebar-footer">
            <span className="avatar">B</span>

            <div>
              <strong>Bayora workspace</strong>
              <small>Safety operations</small>
            </div>

            <Settings2 size={17} />
          </div>
        </aside>
      )}

      <div className="main-shell">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu icon-button"
              onClick={() =>
                setMobileNavOpen((open) => !open)
              }
              aria-label="Toggle navigation"
            >
              {mobileNavOpen ? (
                <X size={20} />
              ) : (
                <Menu size={20} />
              )}
            </button>

            {isHorizontalNav && (
              <a
                href="#overview"
                className="brand topbar-brand"
                onClick={(event) => {
                  event.preventDefault();
                  setPage("overview");
                }}
              >
                <span className="brand-mark">
                  <ShieldCheck size={22} />
                </span>

                <span className="brand-copy">
                  <strong>
                    bayora<span>.</span>
                  </strong>
                  <small>AI SAFETY PLATFORM</small>
                </span>
              </a>
            )}

            <div className="breadcrumb">
              <span>Workspace</span>
              <ChevronRight size={14} />
              <strong>{pageTitle}</strong>
            </div>
          </div>

          <div className="topbar-actions">
            <StatusPill status={apiStatus}>
              {apiStatus === "connected"
                ? "API online"
                : apiStatus === "offline"
                  ? "API offline"
                  : "Connecting"}
            </StatusPill>

            <button
              className="button button-secondary shuffle-button"
              onClick={shuffleLayout}
              title="Shuffle dashboard layout"
            >
              <RefreshCw size={15} />
              <span>Shuffle layout</span>
            </button>
          </div>
        </header>

        {isHorizontalNav && (
          <nav
            className="horizontal-navigation"
            aria-label="Main navigation"
          >
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;

              return (
                <button
                  key={item.id}
                  className={`horizontal-nav-item ${
                    page === item.id ? "active" : ""
                  }`}
                  onClick={() => setPage(item.id)}
                >
                  <Icon size={17} />
                  {item.label}
                </button>
              );
            })}
          </nav>
        )}

        <main className="main-content">
          <div className="page-meta">
            <div className="page-meta-label">
              <span className="meta-dot" />
              SAFETY OPERATIONS
              <span className="meta-divider">/</span>
              {pageTitle.toUpperCase()}
            </div>

            <div className="layout-meta">
              <Command size={13} />
              {layout.template.replaceAll("-", " ")}
              <span>·</span> seed {layout.seed}
            </div>
          </div>

          <div className="page-content" key={page}>
            {renderPage()}
          </div>

          <footer className="app-footer">
            <span>© {new Date().getFullYear()} Bayora</span>

            <span className="footer-center">
              <ShieldCheck size={14} />
              Built for safer AI systems
            </span>

            <button
              className="footer-link"
              onClick={checkHealth}
            >
              <RotateCw size={13} /> Refresh status
            </button>
          </footer>
        </main>
      </div>

      {notice && (
        <div
          className={`toast toast-${notice.type}`}
          role="status"
          aria-live="polite"
        >
          {notice.type === "error" ? (
            <CircleAlert size={18} />
          ) : notice.type === "warning" ? (
            <ShieldAlert size={18} />
          ) : (
            <CheckCircle2 size={18} />
          )}

          <span>{notice.message}</span>

          <button
            onClick={() => setNotice(null)}
            aria-label="Dismiss notification"
          >
            <X size={16} />
          </button>
        </div>
      )}
    </div>
  );
}

export default App;
