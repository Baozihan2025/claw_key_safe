from pathlib import Path
import sys
import os


PATCH_MARKER = "CLAW_KEY_SAFE_REDACTION_PATCH"

HELPER_BLOCK = r"""
const CLAW_KEY_SAFE_REPLACEMENT = process$1?.env?.CLAW_KEY_SAFE_REPLACEMENT || "***REDACTED***";
const CLAW_KEY_SAFE_CACHE_TTL_MS = 60 * 1000;
const CLAW_KEY_SAFE_CONFIG_PATH = process$1?.env?.CLAW_KEY_SAFE_CONFIG_PATH || "/home/node/.openclaw/openclaw.json";
const CLAW_KEY_SAFE_SECRET_ENV_NAME_RE = /(?:^|_)(?:API_KEY|API_TOKEN|APP_SECRET|CLIENT_SECRET|ACCESS_TOKEN|REFRESH_TOKEN|AUTH_TOKEN|GATEWAY_TOKEN|WEBHOOK_SECRET|SIGNING_SECRET|PRIVATE_KEY|TOKEN|SECRET|PASSWORD|LICENSE_KEY)(?:_|$)/i;
const CLAW_KEY_SAFE_SECRET_CONFIG_KEY_RE = /^(?:apiKey|apiToken|appSecret|clientSecret|accessToken|refreshToken|authToken|gatewayToken|webhookSecret|signingSecret|privateKey|licenseKey|token|secret|password)$/i;
const CLAW_KEY_SAFE_SECRET_LABEL_RE = /((?:api[_-]?key|api[_-]?token|app[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|gateway[_-]?token|webhook[_-]?secret|signing[_-]?secret|private[_-]?key|license[_-]?key|authorization|bearer|token|secret|password)\s*[:=]\s*)(["']?)([^\s"'`,}\]]{8,})\2/giu;
const CLAW_KEY_SAFE_URLISH_KEY_RE = /(?:^|_)(?:url|href|src|image|icon|thumb|avatar|photo|poster|media|file)(?:s)?$/i;
let clawKeySafeCache = {
	loadedAt: 0,
	explicitSecrets: []
};
function clawKeySafeEscapeRegExp(value) {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function clawKeySafeNormalizeSecretCandidate(value) {
	if (typeof value !== "string") return null;
	const trimmed = value.trim();
	if (trimmed.length < 8) return null;
	if (/\s/.test(trimmed)) return null;
	return trimmed;
}
function clawKeySafeCollectExplicitSecrets(value, out) {
	if (Array.isArray(value)) {
		for (const entry of value) clawKeySafeCollectExplicitSecrets(entry, out);
		return;
	}
	if (!value || typeof value !== "object") return;
	for (const [key, child] of Object.entries(value)) {
		if (typeof child === "string") {
			if (CLAW_KEY_SAFE_SECRET_CONFIG_KEY_RE.test(key)) {
				const normalized = clawKeySafeNormalizeSecretCandidate(child);
				if (normalized) out.add(normalized);
			}
			continue;
		}
		clawKeySafeCollectExplicitSecrets(child, out);
	}
}
function clawKeySafeLoadExplicitSecrets() {
	const now = Date.now();
	if (now - clawKeySafeCache.loadedAt < CLAW_KEY_SAFE_CACHE_TTL_MS) {
		return clawKeySafeCache.explicitSecrets;
	}
	const collected = new Set();
	for (const [name, value] of Object.entries(process$1.env ?? {})) {
		if (!CLAW_KEY_SAFE_SECRET_ENV_NAME_RE.test(name)) continue;
		const normalized = clawKeySafeNormalizeSecretCandidate(value);
		if (normalized) collected.add(normalized);
	}
	if (existsSync(CLAW_KEY_SAFE_CONFIG_PATH)) {
		try {
			const parsed = JSON5.parse(readFileSync(CLAW_KEY_SAFE_CONFIG_PATH, "utf8"));
			clawKeySafeCollectExplicitSecrets(parsed, collected);
		} catch {}
	}
	const explicitSecrets = [...collected].sort((a, b) => b.length - a.length);
	clawKeySafeCache = {
		loadedAt: now,
		explicitSecrets
	};
	return explicitSecrets;
}
function clawKeySafeRedactExplicit(text) {
	let result = text;
	for (const secret of clawKeySafeLoadExplicitSecrets()) {
		if (!secret || !result.includes(secret)) continue;
		result = result.replace(new RegExp(clawKeySafeEscapeRegExp(secret), "g"), CLAW_KEY_SAFE_REPLACEMENT);
	}
	return result;
}
function clawKeySafeRedactLabeled(text) {
	return text.replace(CLAW_KEY_SAFE_SECRET_LABEL_RE, (_, prefix, quote) => `${prefix}${quote}${CLAW_KEY_SAFE_REPLACEMENT}${quote}`);
}
function clawKeySafeRedactPatterns(text) {
	return text
		.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/giu, `Bearer ${CLAW_KEY_SAFE_REPLACEMENT}`)
		.replace(/\b(?:sk|rk|pk|pat)[-_]\s*[A-Za-z0-9_-]{10,}\b/gu, CLAW_KEY_SAFE_REPLACEMENT)
		.replace(/\bgh[pousr]_\s*[A-Za-z0-9]{20,}\b/gu, CLAW_KEY_SAFE_REPLACEMENT)
		.replace(/\bglpat-[A-Za-z0-9_-]{20,}\b/gu, CLAW_KEY_SAFE_REPLACEMENT)
		.replace(/\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,}\b/gu, CLAW_KEY_SAFE_REPLACEMENT)
		.replace(/\bAIza\s*[0-9A-Za-z\-_]{20,}\b/gu, CLAW_KEY_SAFE_REPLACEMENT)
		.replace(/\bya29\.[0-9A-Za-z\-_\.]+\b/gu, CLAW_KEY_SAFE_REPLACEMENT)
		.replace(/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/gu, CLAW_KEY_SAFE_REPLACEMENT)
		.replace(/\b[A-Za-z0-9_-]{16,}\.[A-Za-z0-9._-]{16,}\.[A-Za-z0-9._-]{8,}\b/gu, CLAW_KEY_SAFE_REPLACEMENT);
}
function clawKeySafeRedactString(text) {
	if (typeof text !== "string" || text.length === 0) return text;
	let result = clawKeySafeRedactExplicit(text);
	result = clawKeySafeRedactLabeled(result);
	result = clawKeySafeRedactPatterns(result);
	return result;
}
function clawKeySafeShouldSkip(key, value) {
	return CLAW_KEY_SAFE_URLISH_KEY_RE.test(key) || /^(?:https?:|data:|file:|mailto:)/i.test(value);
}
function clawKeySafeRedactChannelData(value, keyPath = []) {
	if (typeof value === "string") {
		const currentKey = keyPath.length ? String(keyPath[keyPath.length - 1]) : "";
		if (clawKeySafeShouldSkip(currentKey, value)) return value;
		return clawKeySafeRedactString(value);
	}
	if (Array.isArray(value)) {
		let changed = false;
		const next = value.map((entry, index) => {
			const updated = clawKeySafeRedactChannelData(entry, [...keyPath, String(index)]);
			if (updated !== entry) changed = true;
			return updated;
		});
		return changed ? next : value;
	}
	if (!value || typeof value !== "object") return value;
	let changed = false;
	const next = {};
	for (const [key, child] of Object.entries(value)) {
		const updated = clawKeySafeRedactChannelData(child, [...keyPath, key]);
		next[key] = updated;
		if (updated !== child) changed = true;
	}
	return changed ? next : value;
}
function clawKeySafeRedactPayload(payload) {
	if (!payload || typeof payload !== "object") return payload;
	let changed = false;
	let text = payload.text;
	if (typeof text === "string") {
		const redactedText = clawKeySafeRedactString(text);
		if (redactedText !== text) {
			text = redactedText;
			changed = true;
		}
	}
	let channelData = payload.channelData;
	if (channelData && typeof channelData === "object") {
		const redactedChannelData = clawKeySafeRedactChannelData(channelData, ["channelData"]);
		if (redactedChannelData !== channelData) {
			channelData = redactedChannelData;
			changed = true;
		}
	}
	if (!changed) return payload;
	return {
		...payload,
		...typeof text === "string" ? { text } : {},
		...channelData && typeof channelData === "object" ? { channelData } : {}
	};
}
const CLAW_KEY_SAFE_REDACTION_PATCH = true;
"""


def patch_reply_bundle(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    if PATCH_MARKER in text:
        return False

    anchor = "//#region src/auto-reply/reply/normalize-reply.ts\nfunction normalizeReplyPayload(payload, opts = {}) {"
    if anchor not in text:
        raise RuntimeError(f"normalize-reply anchor not found in {path}")

    text = text.replace(
        anchor,
        f"//#region src/auto-reply/reply/normalize-reply.ts\n{HELPER_BLOCK}\nfunction normalizeReplyPayload(payload, opts = {{}}) {{",
        1,
    )

    tail = '\tif (opts.enableSlackInteractiveReplies && text && hasSlackDirectives(text)) enrichedPayload = parseSlackDirectives(enrichedPayload);\n\treturn enrichedPayload;\n}'
    replacement = '\tif (opts.enableSlackInteractiveReplies && text && hasSlackDirectives(text)) enrichedPayload = parseSlackDirectives(enrichedPayload);\n\tenrichedPayload = clawKeySafeRedactPayload(enrichedPayload);\n\treturn enrichedPayload;\n}'
    if tail not in text:
        raise RuntimeError(f"normalizeReplyPayload return block not found in {path}")
    text = text.replace(tail, replacement, 1)

    path.write_text(text, encoding="utf-8")
    return True


def main() -> int:
    dist_dir = Path(os.environ.get("CLAW_KEY_SAFE_DIST_DIR", "/app/dist"))
    candidates = sorted(dist_dir.glob("reply-*.js"))
    if not candidates:
        raise RuntimeError(f"No reply-*.js bundle found under {dist_dir}")

    patched = 0
    for candidate in candidates:
        body = candidate.read_text(encoding="utf-8")
        if "function normalizeReplyPayload(payload, opts = {}) {" not in body:
            continue
        if patch_reply_bundle(candidate):
            patched += 1

    if patched == 0:
        print("patch already applied or no matching bundle found")
    else:
        print(f"patched {patched} OpenClaw reply bundle(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
