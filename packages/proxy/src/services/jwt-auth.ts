import type { GatewayRepositories } from '@octafuse/core';
import {
	createRemoteJWKSet, errors, importSPKI, jwksCache, jwtVerify,
	type JWKSCacheInput,
} from 'jose';
import { resolveAuthenticatedKey, type AuthenticatedApiKey } from './api-key-auth';
import { provisionJwtUser, type JwtAutoProvision } from './jwt-provision';

/** Configured by the operator, never by JWT headers or claims. One issuer per gateway. */
export type JwtAuthConfig = {
	issuer: string;
	audience: string;
	algorithm: 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'PS384' | 'PS512' | 'ES256' | 'ES384';
	publicKey?: string;
	jwksUrl?: string;
	/** Defaults to at+jwt. Set JWT only for issuers that use a generic access-token typ. */
	tokenType: string;
	requiredScopes: string[];
	/** Omit for manual enrollment. Defaults are applied only when a user is first created. */
	autoProvision?: JwtAutoProvision;
};

export class JwtAuthError extends Error {
	constructor(public readonly status: 401 | 403 | 503, message: string) {
		super(message);
	}
}

const algorithms = new Set(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384']);

export function parseJwtAuthConfig(raw: string): JwtAuthConfig {
	try {
		const value = JSON.parse(raw);
		if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
		const allowed = new Set(['issuer', 'audience', 'algorithm', 'publicKey', 'jwksUrl', 'tokenType', 'requiredScopes', 'autoProvision']);
		if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error();
		for (const field of ['issuer', 'audience', 'algorithm']) {
			if (typeof value[field] !== 'string' || !value[field].trim()) throw new Error();
		}
		if (!algorithms.has(value.algorithm)) throw new Error();
		for (const field of ['publicKey', 'jwksUrl', 'tokenType']) {
			if (value[field] !== undefined && (typeof value[field] !== 'string' || !value[field].trim())) throw new Error();
		}
		if (Boolean(value.publicKey) === Boolean(value.jwksUrl)) throw new Error();
		if (value.jwksUrl) {
			const url = new URL(value.jwksUrl);
			if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error();
		}
		if (value.requiredScopes !== undefined && (
			!Array.isArray(value.requiredScopes) ||
			value.requiredScopes.some((scope: unknown) => typeof scope !== 'string' || !scope || /\s/.test(scope))
		)) throw new Error();
		let autoProvision: JwtAutoProvision | undefined;
		if (value.autoProvision !== undefined) {
			const policy = value.autoProvision;
			if (!policy || typeof policy !== 'object' || Array.isArray(policy) ||
				Object.keys(policy).some((key) => !['budgetMax', 'budgetPeriod', 'rpm'].includes(key))) throw new Error();
			if (policy.budgetMax !== null && (typeof policy.budgetMax !== 'number' ||
				!Number.isFinite(policy.budgetMax) || policy.budgetMax < 0 || policy.budgetMax > 1e12)) throw new Error();
			const budgetPeriod = policy.budgetPeriod ?? 'none';
			if (!['none', 'daily', 'weekly', 'monthly'].includes(budgetPeriod)) throw new Error();
			const rpm = policy.rpm === undefined ? 60 : policy.rpm;
			if (rpm !== null && (!Number.isSafeInteger(rpm) || rpm < 0)) throw new Error();
			// Match the narrowest supported storage schema (MySQL external_system VARCHAR(128)).
			if ([...value.issuer].length > 128) throw new Error();
			autoProvision = { budgetMax: policy.budgetMax, budgetPeriod, rpm };
		}
		return { ...value, tokenType: value.tokenType ?? 'at+jwt', requiredScopes: value.requiredScopes ?? [], autoProvision };
	} catch {
		throw new JwtAuthError(503, 'JWT authentication is misconfigured');
	}
}

// Cache only public verification material. No user/session state or in-flight I/O
// is shared across Worker requests. A configuration change discards the old cache.
let cached: { raw: string; config: JwtAuthConfig; publicKey?: CryptoKey; jwks: JWKSCacheInput } | undefined;

export async function authenticateJwt(
	repos: GatewayRepositories,
	token: string,
	rawConfig: string,
): Promise<AuthenticatedApiKey> {
	if (!cached || cached.raw !== rawConfig) {
		cached = { raw: rawConfig, config: parseJwtAuthConfig(rawConfig), jwks: {} };
	}
	const entry = cached;
	const config = entry.config;
	if (token.length > 16_384) throw new JwtAuthError(401, 'Invalid access token');
	let key;
	try {
		if (config.publicKey) {
			entry.publicKey ??= await importSPKI(config.publicKey.replace(/\\n/g, '\n'), config.algorithm);
			key = entry.publicKey;
		} else {
			key = createRemoteJWKSet(new URL(config.jwksUrl!), {
				timeoutDuration: 5_000,
				cacheMaxAge: 600_000,
				cooldownDuration: 30_000,
				[jwksCache]: entry.jwks,
			});
		}
	} catch {
		throw new JwtAuthError(503, 'JWT authentication is misconfigured');
	}

	let payload;
	try {
		({ payload } = await jwtVerify(token, key, {
			algorithms: [config.algorithm],
			issuer: config.issuer,
			audience: config.audience,
			typ: config.tokenType,
			requiredClaims: ['iss', 'aud', 'sub', 'exp'],
			clockTolerance: 5,
		}));
	} catch (error) {
		if (error instanceof errors.JOSEError && ![
			'ERR_JWKS_TIMEOUT', 'ERR_JWKS_INVALID', 'ERR_JWK_INVALID', 'ERR_JOSE_GENERIC',
		].includes(error.code)) {
			throw new JwtAuthError(401, 'Invalid access token');
		}
		throw new JwtAuthError(503, 'JWT verification is temporarily unavailable');
	}
	if (typeof payload.sub !== 'string' || !payload.sub.trim()) {
		throw new JwtAuthError(401, 'Invalid access token');
	}
	const scopes = new Set(typeof payload.scope === 'string' ? payload.scope.split(/\s+/) : []);
	if (config.requiredScopes.some((scope) => !scopes.has(scope))) {
		throw new JwtAuthError(403, 'Insufficient access token scope');
	}

	// Never map by email, or accept a local user/key ID supplied by the token.
	let user = await repos.users.getByExternalPair(config.issuer, payload.sub);
	if (!user && config.autoProvision) {
		if ([...payload.sub].length > 512) throw new JwtAuthError(401, 'Invalid access token subject');
		try {
			user = await provisionJwtUser(repos, config.issuer, payload.sub, config.autoProvision);
		} catch {
			throw new JwtAuthError(503, 'JWT user provisioning is temporarily unavailable');
		}
	}
	// Check exact identity even when a storage collation performs case-insensitive comparisons.
	if (!user || user.status !== 'active' || user.external_system !== config.issuer || user.external_user_id !== payload.sub) {
		throw new JwtAuthError(403, 'Gateway access is not enabled');
	}
	let keyId: unknown;
	try {
		keyId = JSON.parse(user.metadata ?? '{}')?.jwt_api_key_id;
	} catch { /* Invalid metadata fails closed. */ }
	if (typeof keyId !== 'string' || !keyId) throw new JwtAuthError(403, 'Gateway access is not enabled');
	const row = await repos.apiKeys.getApiKeyWithUserById(keyId);
	if (!row || row.status !== 'active' || row.user_id !== user.id) {
		throw new JwtAuthError(403, 'Gateway access is not enabled');
	}
	return resolveAuthenticatedKey(repos, row);
}
