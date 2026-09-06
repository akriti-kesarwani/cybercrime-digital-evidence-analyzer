// ============================================================
// Evidence Analysis Edge Function
// ============================================================
// This function is the "analysis engine" of the application.
// It receives an evidence file ID, downloads the file from storage,
// parses it based on file type, extracts normalized events,
// runs 7 detection rules, generates alerts, extracts indicators,
// and updates the case risk score.
//
// Cybersecurity concepts used here:
// - Log parsing: converting different log formats into a common schema
// - Detection rules: pattern matching to find suspicious activity
// - Event correlation: linking related events across log sources
// - Risk scoring: transparent scoring based on multiple factors
// - Indicators of Compromise (IOCs): IPs, usernames, filenames
// ============================================================

import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface ParsedEvent {
  timestamp: string;
  event_type: string;
  username: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  source: string;
  description: string | null;
  severity: string;
  raw_data: Record<string, unknown>;
}

interface DetectionAlert {
  alert_type: string;
  severity: string;
  confidence: number;
  reason: string;
  related_event_ids: string[];
  detection_rule: string;
}

// ============================================================
// PARSERS — each converts a file format into normalized events
// ============================================================

function parseAuthLog(content: string, filename: string): ParsedEvent[] {
  const events: ParsedEvent[] = [];
  const lines = content.split("\n").filter((l) => l.trim());

  for (const line of lines) {
    // Format: 2026-09-01 10:01:22 user=admin ip=10.0.0.15 status=FAILED
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+user=(\S+)\s+ip=(\S+)\s+status=(\S+)/
    );
    if (!match) continue;

    const [, timestamp, username, ip, status] = match;

    let event_type = "OTHER";
    let severity = "LOW";

    if (status === "FAILED") {
      event_type = "LOGIN_FAILED";
      severity = "MEDIUM";
    } else if (status === "SUCCESS") {
      event_type = "LOGIN_SUCCESS";
      severity = "LOW";
    } else if (status === "LOGOUT") {
      event_type = "LOGOUT";
      severity = "LOW";
    } else if (status === "LOGIN") {
      event_type = "LOGIN_SUCCESS";
      severity = "LOW";
    }

    events.push({
      timestamp,
      event_type,
      username,
      source_ip: ip,
      destination_ip: null,
      source: filename,
      description: `Authentication ${status.toLowerCase()} for user ${username} from ${ip}`,
      severity,
      raw_data: { raw_line: line, username, ip, status },
    });
  }

  return events;
}

function parseWebLog(content: string, filename: string): ParsedEvent[] {
  const events: ParsedEvent[] = [];
  const lines = content.split("\n").filter((l) => l.trim());

  for (const line of lines) {
    // Format: 2026-09-01 10:05:45 10.0.0.15 GET /admin/dashboard 200
    const match = line.match(
      /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)/
    );
    if (!match) continue;

    const [, timestamp, ip, method, path, statusCode] = match;
    const status = parseInt(statusCode);

    let event_type = "OTHER";
    let severity = "LOW";

    if (path.includes("/admin") || path.includes("/api/users") || path.includes("passwords")) {
      event_type = "FILE_ACCESS";
      severity = "MEDIUM";
    } else if (method === "PUT" || method === "POST") {
      event_type = "FILE_MODIFY";
      severity = "MEDIUM";
    } else {
      event_type = "NETWORK_CONNECTION";
      severity = "LOW";
    }

    if (status >= 400) {
      severity = "MEDIUM";
    }

    events.push({
      timestamp,
      event_type,
      username: null,
      source_ip: ip,
      destination_ip: null,
      source: filename,
      description: `${method} ${path} → ${status}`,
      severity,
      raw_data: { raw_line: line, ip, method, path, status },
    });
  }

  return events;
}

function parseCsv(content: string, filename: string): ParsedEvent[] {
  const events: ParsedEvent[] = [];
  const lines = content.split("\n").filter((l) => l.trim());
  if (lines.length < 2) return events;

  const headers = lines[0].split(",").map((h) => h.trim());

  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(",").map((v) => v.trim());
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => {
      row[h] = values[idx] ?? "";
    });

    const timestamp = row.timestamp || row.time || row.date;
    if (!timestamp) continue;

    let event_type = "OTHER";
    let severity = "LOW";
    let username = row.username || null;
    let source_ip = row.source_ip || row.ip || null;
    let destination_ip = row.destination_ip || row.dest_ip || null;
    let description: string | null = null;

    const action = (row.action || "").toUpperCase();

    if (filename.includes("file_events") || row.filename) {
      if (action === "READ") {
        event_type = "FILE_ACCESS";
        severity = "MEDIUM";
        description = `Read file: ${row.filename}`;
      } else if (action === "MODIFIED" || action === "MODIFY" || action === "WRITE") {
        event_type = "FILE_MODIFY";
        severity = "HIGH";
        description = `Modified file: ${row.filename}`;
      } else if (action === "DELETED" || action === "DELETE") {
        event_type = "FILE_DELETE";
        severity = "HIGH";
        description = `Deleted file: ${row.filename}`;
      }

      // Check for sensitive files
      const sensitiveFiles = ["password", "config", "secret", "key", "credential", "users.csv"];
      if (row.filename && sensitiveFiles.some((s) => row.filename.toLowerCase().includes(s))) {
        severity = "HIGH";
        description = `Sensitive file access: ${row.filename}`;
      }
    } else if (filename.includes("network") || row.protocol) {
      if (action === "BLOCKED") {
        event_type = "NETWORK_BLOCKED";
        severity = "HIGH";
        description = `Network blocked: ${source_ip} → ${destination_ip}:${row.port}`;
      } else if (action === "DNS_QUERY" || action === "DNS") {
        event_type = "NETWORK_DNS";
        severity = "LOW";
        description = `DNS query from ${source_ip}`;
      } else {
        event_type = "NETWORK_CONNECTION";
        severity = "LOW";
        description = `Connection: ${source_ip} → ${destination_ip}:${row.port} (${row.protocol})`;
      }
    }

    events.push({
      timestamp,
      event_type,
      username,
      source_ip,
      destination_ip,
      source: filename,
      description,
      severity,
      raw_data: row,
    });
  }

  return events;
}

function parseJson(content: string, filename: string): ParsedEvent[] {
  const events: ParsedEvent[] = [];

  try {
    const data = JSON.parse(content);
    const items = Array.isArray(data) ? data : [data];

    for (const item of items) {
      const timestamp = item.timestamp || item.time || item.date;
      if (!timestamp) continue;

      events.push({
        timestamp,
        event_type: item.event_type || "OTHER",
        username: item.username || null,
        source_ip: item.source_ip || item.ip || null,
        destination_ip: item.destination_ip || null,
        source: filename,
        description: item.description || null,
        severity: item.severity || "LOW",
        raw_data: item,
      });
    }
  } catch {
    // Invalid JSON
  }

  return events;
}

function parseEvidence(content: string, filename: string, fileType: string): ParsedEvent[] {
  if (fileType === ".json") {
    return parseJson(content, filename);
  } else if (fileType === ".csv") {
    return parseCsv(content, filename);
  } else if (filename.includes("auth") || fileType === ".log") {
    // Try auth log format first, fall back to web log
    const authEvents = parseAuthLog(content, filename);
    if (authEvents.length > 0) return authEvents;
    return parseWebLog(content, filename);
  } else if (fileType === ".txt") {
    const authEvents = parseAuthLog(content, filename);
    if (authEvents.length > 0) return authEvents;
    const webEvents = parseWebLog(content, filename);
    if (webEvents.length > 0) return webEvents;
    return parseJson(content, filename);
  }

  return [];
}

// ============================================================
// DETECTION RULES — 7 rule-based detectors
// ============================================================

interface StoredEvent {
  id: string;
  timestamp: string;
  event_type: string;
  username: string | null;
  source_ip: string | null;
  severity: string;
  source: string | null;
}

function runDetectionRules(events: StoredEvent[]): DetectionAlert[] {
  const alerts: DetectionAlert[] = [];

  // RULE 1: Repeated failed logins from same IP (5+ within 5 minutes)
  const failedByIp: Record<string, StoredEvent[]> = {};
  for (const ev of events) {
    if (ev.event_type === "LOGIN_FAILED" && ev.source_ip) {
      if (!failedByIp[ev.source_ip]) failedByIp[ev.source_ip] = [];
      failedByIp[ev.source_ip].push(ev);
    }
  }

  for (const [ip, ipEvents] of Object.entries(failedByIp)) {
    // Sort by timestamp
    const sorted = [...ipEvents].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    // Sliding window: 5+ failures within 5 minutes
    for (let i = 0; i < sorted.length; i++) {
      const windowStart = new Date(sorted[i].timestamp).getTime();
      const windowEnd = windowStart + 5 * 60 * 1000;
      const windowEvents = sorted.filter(
        (e) =>
          new Date(e.timestamp).getTime() >= windowStart &&
          new Date(e.timestamp).getTime() <= windowEnd
      );

      if (windowEvents.length >= 5) {
        alerts.push({
          alert_type: "Potential Brute Force",
          severity: "HIGH",
          confidence: Math.min(60 + windowEvents.length * 5, 95),
          reason: `${windowEvents.length} failed login attempts from ${ip} within 5 minutes.`,
          related_event_ids: windowEvents.map((e) => e.id),
          detection_rule: "RULE_1_BRUTE_FORCE",
        });
        break; // One alert per IP
      }
    }
  }

  // RULE 2: Multiple failed logins followed by successful login (account compromise)
  const byUser: Record<string, StoredEvent[]> = {};
  for (const ev of events) {
    if (ev.username) {
      if (!byUser[ev.username]) byUser[ev.username] = [];
      byUser[ev.username].push(ev);
    }
  }

  for (const [username, userEvents] of Object.entries(byUser)) {
    const sorted = [...userEvents].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    let failedStreak = 0;
    let failedEvents: StoredEvent[] = [];

    for (const ev of sorted) {
      if (ev.event_type === "LOGIN_FAILED") {
        failedStreak++;
        failedEvents.push(ev);
      } else if (ev.event_type === "LOGIN_SUCCESS" && failedStreak >= 3) {
        alerts.push({
          alert_type: "Potential Account Compromise",
          severity: "CRITICAL",
          confidence: Math.min(70 + failedStreak * 5, 95),
          reason: `${failedStreak} failed login attempts followed by successful login for user ${username}.`,
          related_event_ids: [...failedEvents.map((e) => e.id), ev.id],
          detection_rule: "RULE_2_ACCOUNT_COMPROMISE",
        });
        failedStreak = 0;
        failedEvents = [];
      } else if (ev.event_type === "LOGIN_SUCCESS") {
        failedStreak = 0;
        failedEvents = [];
      }
    }
  }

  // RULE 3: Sensitive file access
  const sensitiveKeywords = ["password", "config", "secret", "key", "credential", "users.csv"];
  for (const ev of events) {
    if (ev.event_type === "FILE_ACCESS") {
      const evData = ev as unknown as Record<string, unknown>;
      const raw = evData.raw_data as Record<string, string> | undefined;
      const filename = raw?.filename || raw?.path || "";
      if (sensitiveKeywords.some((s) => filename.toLowerCase().includes(s))) {
        alerts.push({
          alert_type: "Sensitive File Access",
          severity: "HIGH",
          confidence: 75,
          reason: `Access to sensitive file: ${filename}`,
          related_event_ids: [ev.id],
          detection_rule: "RULE_3_SENSITIVE_ACCESS",
        });
      }
    }
  }

  // RULE 4: Sensitive file modification
  for (const ev of events) {
    if (ev.event_type === "FILE_MODIFY") {
      const evData = ev as unknown as Record<string, unknown>;
      const raw = evData.raw_data as Record<string, string> | undefined;
      const filename = raw?.filename || raw?.path || "";
      if (sensitiveKeywords.some((s) => filename.toLowerCase().includes(s))) {
        alerts.push({
          alert_type: "Sensitive File Modification",
          severity: "CRITICAL",
          confidence: 85,
          reason: `Modification of sensitive file: ${filename}`,
          related_event_ids: [ev.id],
          detection_rule: "RULE_4_SENSITIVE_MODIFICATION",
        });
      } else {
        alerts.push({
          alert_type: "File Modification",
          severity: "MEDIUM",
          confidence: 50,
          reason: `File modified: ${filename}`,
          related_event_ids: [ev.id],
          detection_rule: "RULE_4_FILE_MODIFICATION",
        });
      }
    }
  }

  // RULE 5: Unusual login time (outside 8am-6pm)
  for (const ev of events) {
    if (ev.event_type === "LOGIN_SUCCESS") {
      const hour = new Date(ev.timestamp).getHours();
      if (hour < 8 || hour > 18) {
        alerts.push({
          alert_type: "Unusual Login Time",
          severity: "MEDIUM",
          confidence: 60,
          reason: `Login at ${hour}:${String(new Date(ev.timestamp).getMinutes()).padStart(2, "0")} (outside business hours 08:00-18:00).`,
          related_event_ids: [ev.id],
          detection_rule: "RULE_5_UNUSUAL_TIME",
        });
      }
    }
  }

  // RULE 6: Large number of events from one source (potential automated activity)
  const eventCountByIp: Record<string, number> = {};
  for (const ev of events) {
    if (ev.source_ip) {
      eventCountByIp[ev.source_ip] = (eventCountByIp[ev.source_ip] || 0) + 1;
    }
  }

  for (const [ip, count] of Object.entries(eventCountByIp)) {
    if (count >= 20) {
      const ipEvents = events.filter((e) => e.source_ip === ip);
      alerts.push({
        alert_type: "Potential Automated Activity",
        severity: "MEDIUM",
        confidence: 65,
        reason: `${count} events from source IP ${ip} — potential automated activity.`,
        related_event_ids: ipEvents.slice(0, 20).map((e) => e.id),
        detection_rule: "RULE_6_HIGH_VOLUME",
      });
    }
  }

  // RULE 7: Suspicious event sequence (failed logins → success → sensitive file access)
  for (const [username, userEvents] of Object.entries(byUser)) {
    const sorted = [...userEvents].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    let failedCount = 0;
    let successIdx = -1;

    for (let i = 0; i < sorted.length; i++) {
      if (sorted[i].event_type === "LOGIN_FAILED") {
        failedCount++;
      } else if (sorted[i].event_type === "LOGIN_SUCCESS" && failedCount >= 3) {
        successIdx = i;
        break;
      } else if (sorted[i].event_type === "LOGIN_SUCCESS") {
        failedCount = 0;
      }
    }

    if (successIdx >= 0) {
      const afterSuccess = sorted.slice(successIdx + 1);
      const sensitiveAccess = afterSuccess.find(
        (e) => e.event_type === "FILE_ACCESS" || e.event_type === "FILE_MODIFY"
      );

      if (sensitiveAccess) {
        const seqEvents = [
          ...sorted.slice(0, successIdx + 1).slice(-5),
          sensitiveAccess,
        ];
        alerts.push({
          alert_type: "Suspicious Event Sequence",
          severity: "CRITICAL",
          confidence: 90,
          reason: `Failed logins → successful login → sensitive file access for user ${username}. This pattern may indicate account compromise followed by data access.`,
          related_event_ids: seqEvents.map((e) => e.id),
          detection_rule: "RULE_7_SUSPICIOUS_SEQUENCE",
        });
      }
    }
  }

  return alerts;
}

// ============================================================
// INDICATOR EXTRACTION
// ============================================================

interface ExtractedIndicator {
  type: string;
  value: string;
  occurrence_count: number;
}

function extractIndicators(events: StoredEvent[]): ExtractedIndicator[] {
  const indicators: Record<string, ExtractedIndicator> = {};

  function addIndicator(type: string, value: string) {
    if (!value) return;
    const key = `${type}:${value}`;
    if (!indicators[key]) {
      indicators[key] = { type, value, occurrence_count: 0 };
    }
    indicators[key].occurrence_count++;
  }

  for (const ev of events) {
    if (ev.source_ip) addIndicator("IP", ev.source_ip);
    if (ev.username) addIndicator("USERNAME", ev.username);

    const evData = ev as unknown as Record<string, unknown>;
    const raw = evData.raw_data as Record<string, string> | undefined;
    if (raw?.filename) addIndicator("FILENAME", raw.filename);
    if (raw?.path) addIndicator("FILENAME", raw.path);
    if (raw?.destination_ip) addIndicator("IP", raw.destination_ip);
    if (raw?.dest_ip) addIndicator("IP", raw.dest_ip);
  }

  return Object.values(indicators);
}

// ============================================================
// RISK SCORING
// ============================================================

function calculateRiskScore(
  alerts: DetectionAlert[],
  eventCount: number,
  indicatorCount: number
): { level: string; total_score: number; max_score: number; explanation: string } {
  const severityWeights: Record<string, number> = {
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
  };

  let score = 0;
  let maxScore = 100;

  // Factor 1: Alert severity (max 40 points)
  let alertScore = 0;
  for (const alert of alerts) {
    alertScore += severityWeights[alert.severity] * 5;
  }
  alertScore = Math.min(alertScore, 40);
  score += alertScore;

  // Factor 2: Event volume (max 20 points)
  const volumeScore = Math.min(Math.floor(eventCount / 10), 20);
  score += volumeScore;

  // Factor 3: Indicator count (max 15 points)
  const indicatorScore = Math.min(indicatorCount * 2, 15);
  score += indicatorScore;

  // Factor 4: Critical alert presence (max 25 points)
  const hasCritical = alerts.some((a) => a.severity === "CRITICAL");
  const hasHigh = alerts.some((a) => a.severity === "HIGH");
  if (hasCritical) score += 25;
  else if (hasHigh) score += 15;

  score = Math.min(score, maxScore);

  let level = "LOW";
  if (score >= 75) level = "CRITICAL";
  else if (score >= 50) level = "HIGH";
  else if (score >= 25) level = "MEDIUM";

  const explanation = `Risk score: ${score}/${maxScore}. ` +
    `Alert severity contribution: ${alertScore}/40. ` +
    `Event volume: ${volumeScore}/20. ` +
    `Indicators: ${indicatorScore}/15. ` +
    `Critical/high alert bonus: ${hasCritical ? 25 : hasHigh ? 15 : 0}/25. ` +
    `Result: ${level}.`;

  return { level, total_score: score, max_score: maxScore, explanation };
}

// ============================================================
// MAIN HANDLER
// ============================================================

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const { evidence_id, case_id } = await req.json();

    if (!evidence_id || !case_id) {
      return new Response(
        JSON.stringify({ error: "evidence_id and case_id are required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // 1. Fetch evidence record
    const { data: evidence, error: evidenceError } = await supabase
      .from("evidence")
      .select("*")
      .eq("id", evidence_id)
      .maybeSingle();

    if (evidenceError || !evidence) {
      return new Response(
        JSON.stringify({ error: "Evidence not found" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 2. Download file from storage
    const { data: fileData, error: downloadError } = await supabase.storage
      .from("evidence")
      .download(evidence.storage_path);

    if (downloadError || !fileData) {
      return new Response(
        JSON.stringify({ error: "Failed to download evidence file" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const content = await fileData.text();

    // 3. Parse evidence
    const parsedEvents = parseEvidence(content, evidence.filename, evidence.file_type);

    if (parsedEvents.length === 0) {
      // Mark as parsed even if no events found
      await supabase
        .from("evidence")
        .update({ parsed: true })
        .eq("id", evidence_id);

      return new Response(
        JSON.stringify({
          success: true,
          events_extracted: 0,
          message: "No events could be parsed from this file.",
        }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // 4. Insert events into database
    const eventsToInsert = parsedEvents.map((ev) => ({
      case_id,
      evidence_id,
      timestamp: ev.timestamp,
      event_type: ev.event_type,
      username: ev.username,
      source_ip: ev.source_ip,
      destination_ip: ev.destination_ip,
      source: ev.source,
      description: ev.description,
      severity: ev.severity,
      raw_data: ev.raw_data,
    }));

    const { data: insertedEvents, error: insertError } = await supabase
      .from("events")
      .insert(eventsToInsert)
      .select("id, timestamp, event_type, username, source_ip, severity, source");

    if (insertError) {
      return new Response(
        JSON.stringify({ error: "Failed to insert events: " + insertError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const storedEvents = (insertedEvents ?? []) as unknown as StoredEvent[];

    // 5. Run detection rules
    const newAlerts = runDetectionRules(storedEvents);

    // 6. Insert alerts
    if (newAlerts.length > 0) {
      const alertsToInsert = newAlerts.map((a) => ({
        case_id,
        alert_type: a.alert_type,
        severity: a.severity,
        confidence: a.confidence,
        reason: a.reason,
        related_event_ids: a.related_event_ids,
        detection_rule: a.detection_rule,
      }));

      await supabase.from("alerts").insert(alertsToInsert);
    }

    // 7. Extract and upsert indicators
    const extractedIndicators = extractIndicators(storedEvents);

    // Fetch existing indicators for this case
    const { data: existingIndicators } = await supabase
      .from("indicators")
      .select("id, type, value, occurrence_count")
      .eq("case_id", case_id);

    const existingMap: Record<string, string> = {};
    for (const ind of existingIndicators ?? []) {
      existingMap[`${ind.type}:${ind.value}`] = ind.id;
    }

    for (const ind of extractedIndicators) {
      const key = `${ind.type}:${ind.value}`;
      if (existingMap[key]) {
        // Update count
        const existing = (existingIndicators ?? []).find(
          (e) => e.type === ind.type && e.value === ind.value
        );
        await supabase
          .from("indicators")
          .update({ occurrence_count: (existing?.occurrence_count ?? 0) + ind.occurrence_count })
          .eq("id", existingMap[key]);
      } else {
        await supabase.from("indicators").insert({
          case_id,
          type: ind.type,
          value: ind.value,
          occurrence_count: ind.occurrence_count,
        });
      }
    }

    // 8. Calculate risk score and update case
    const { data: allCaseEvents } = await supabase
      .from("events")
      .select("id, event_type, username, source_ip, severity, source, timestamp")
      .eq("case_id", case_id);

    const { data: allCaseAlerts } = await supabase
      .from("alerts")
      .select("severity")
      .eq("case_id", case_id);

    const { data: allCaseIndicators } = await supabase
      .from("indicators")
      .select("id")
      .eq("case_id", case_id);

    const allEventsForDetection = (allCaseEvents ?? []) as unknown as StoredEvent[];
    const allAlerts = runDetectionRules(allEventsForDetection);
    const riskScore = calculateRiskScore(
      allAlerts,
      allCaseEvents?.length ?? 0,
      allCaseIndicators?.length ?? 0
    );

    await supabase
      .from("cases")
      .update({
        risk_level: riskScore.level,
        updated_at: new Date().toISOString(),
      })
      .eq("id", case_id);

    // 9. Mark evidence as parsed
    await supabase
      .from("evidence")
      .update({ parsed: true })
      .eq("id", evidence_id);

    // 10. Write audit log
    await supabase.from("audit_logs").insert({
      action: "EVIDENCE_ANALYZED",
      resource: "evidence",
      resource_id: evidence_id,
      metadata: {
        case_id,
        events_extracted: parsedEvents.length,
        alerts_generated: newAlerts.length,
        indicators_extracted: extractedIndicators.length,
        risk_level: riskScore.level,
      },
    });

    return new Response(
      JSON.stringify({
        success: true,
        events_extracted: parsedEvents.length,
        alerts_generated: newAlerts.length,
        indicators_extracted: extractedIndicators.length,
        risk_level: riskScore.level,
        risk_explanation: riskScore.explanation,
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
