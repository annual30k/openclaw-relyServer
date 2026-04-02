export function extractSessionKeysFromPayload(payload: unknown): string[] {
  const payloadRecord =
    payload && typeof payload === "object" && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : undefined;
  const rawItems =
    Array.isArray(payloadRecord?.sessions) ? payloadRecord.sessions
      : Array.isArray(payloadRecord?.items) ? payloadRecord.items
        : Array.isArray(payloadRecord?.list) ? payloadRecord.list
          : Array.isArray(payload) ? payload
            : [];

  const deduped = new Set<string>(["main"]);
  for (const entry of rawItems) {
    if (typeof entry === "string" && entry.trim()) {
      deduped.add(entry.trim());
      continue;
    }
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      continue;
    }
    const record = entry as Record<string, unknown>;
    const sessionKeyRaw =
      typeof record.key === "string" ? record.key
        : typeof record.sessionKey === "string" ? record.sessionKey
          : typeof record.id === "string" ? record.id
            : typeof record.session === "string" ? record.session
              : undefined;
    const sessionKey = sessionKeyRaw?.trim();
    if (sessionKey) {
      deduped.add(sessionKey);
    }
  }

  return Array.from(deduped);
}

export function isIgnorableSessionDeleteError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  const normalized = message.trim().toLowerCase();
  return (
    normalized.includes("not_found") ||
    normalized.includes("session not found") ||
    normalized.includes("cannot delete the main session") ||
    (normalized.includes("main session") && normalized.includes("cannot delete"))
  );
}
