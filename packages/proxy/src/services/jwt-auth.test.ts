import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import { Hono } from 'hono';
import { exportJWK, exportSPKI, generateKeyPair, SignJWT } from 'jose';
import type { GatewayRepositories, ResolvedGatewayKeyRow, UserRow } from '@octafuse/core';
import type { Env } from '../app';
import { requireApiKey } from '../middleware/auth';
import { authenticateJwt, JwtAuthError, parseJwtAuthConfig } from './jwt-auth';

let privateKey: CryptoKey;
let publicKey: CryptoKey;
let config: string;
const issuer = 'https://login.example.test';
const audience = 'octafuse';
const now = () => Math.floor(Date.now() / 1000);
before(async () => {
	({ privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true }));
	config = JSON.stringify({ issuer, audience, algorithm: 'RS256', publicKey: await exportSPKI(publicKey), requiredScopes: ['ai:invoke'] });
});

function fixture() {
	const user: UserRow = {
		id: crypto.randomUUID(), email: 'user@example.test', status: 'active',
		external_system: issuer, external_user_id: 'subject-1',
		metadata: JSON.stringify({ jwt_api_key_id: 'billing-key' }),
		budget_max: 10, budget_base: 10, budget_spent: 2, budget_period: 'none', budget_reset_at: null,
		wallet_granted: 5, wallet_spent: 1, rate_limit: null, charged_cost_factors: null,
		created_at: '', updated_at: '',
	};
	const row: ResolvedGatewayKeyRow = {
		...user, id: 'billing-key', key: 'sk-existing-key', user_id: user.id,
		name: 'JWT billing', metadata: null, last_used_at: null,
		user_email: user.email, user_metadata: user.metadata, user_charged_cost_factors: null, user_rate_limit: null,
	};
	const lookups: string[][] = [];
	const repos = {
		users: { getByExternalPair: async (iss: string, sub: string) => {
			lookups.push([iss, sub]);
			return iss === user.external_system && sub === user.external_user_id ? user : null;
		} },
		apiKeys: {
			getApiKeyWithUserById: async (id: string) => id === row.id ? row : null,
			getApiKeyWithUserByKey: async (key: string) => key === row.key ? row : null,
		},
	} as unknown as GatewayRepositories;
	return { user, row, repos, lookups };
}

function token(overrides: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
	return new SignJWT({ iss: issuer, aud: audience, sub: 'subject-1', exp: now() + 3600, scope: 'ai:invoke', ...overrides })
		.setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', ...header }).sign(privateKey);
}

function status(expected: number) {
	return (error: unknown) => error instanceof JwtAuthError && error.status === expected;
}

describe('external JWT authentication', () => {
	it('maps issuer + subject and retains the real billing identity and budget', async () => {
		const { repos, user, lookups } = fixture();
		const result = await authenticateJwt(repos, await token({ email: 'untrusted@example.test', user_id: 'another-user' }), config);
		assert.equal(result.userId, user.id);
		assert.equal(result.keyId, 'billing-key');
		assert.equal(result.userEmail, user.email);
		assert.equal(result.budgetSpent, 2);
		assert.equal(result.walletGranted, 5);
		assert.deepEqual(lookups, [[issuer, 'subject-1']]);
	});

	for (const [name, claims, header] of [
		['expired', { exp: now() - 60 }, {}],
		['not yet valid', { nbf: now() + 3600 }, {}],
		['wrong issuer', { iss: 'https://attacker.test' }, {}],
		['wrong audience', { aud: 'another-api' }, {}],
		['missing expiry', { exp: undefined }, {}],
		['missing subject', { sub: undefined }, {}],
		['empty subject', { sub: '' }, {}],
		['ID token type', {}, { typ: 'JWT' }],
	] as const) {
		it(`rejects ${name} before accessing the user database`, async () => {
			const { repos, lookups } = fixture();
			await assert.rejects(authenticateJwt(repos, await token(claims, header), config), status(401));
			assert.equal(lookups.length, 0);
		});
	}

	it('rejects forged signatures, unsigned tokens, HS256 and malformed tokens', async () => {
		const { repos, lookups } = fixture();
		const other = await generateKeyPair('RS256');
		const claims = { iss: issuer, aud: audience, sub: 'subject-1', exp: now() + 3600 };
		const forged = await new SignJWT(claims).setProtectedHeader({ alg: 'RS256', typ: 'at+jwt' }).sign(other.privateKey);
		const symmetric = await new SignJWT(claims).setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' }).sign(new TextEncoder().encode('secret'));
		const unsigned = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.`;
		for (const value of [forged, symmetric, unsigned, 'bad.jwt.value', 'a'.repeat(16_385)]) {
			await assert.rejects(authenticateJwt(repos, value, config), status(401));
		}
		assert.equal(lookups.length, 0);
	});

	it('requires every configured scope', async () => {
		await assert.rejects(authenticateJwt(fixture().repos, await token({ scope: 'ai:read' }), config), status(403));
	});

	it('rejects unknown users, disabled users, missing binding, revoked keys and cross-user keys', async () => {
		await assert.rejects(authenticateJwt(fixture().repos, await token({ sub: 'unknown' }), config), status(403));
		for (const change of [
			(f: ReturnType<typeof fixture>) => { f.user.status = 'disabled'; },
			(f: ReturnType<typeof fixture>) => { f.user.metadata = '{}'; },
			(f: ReturnType<typeof fixture>) => { f.user.metadata = 'broken'; },
			(f: ReturnType<typeof fixture>) => { f.row.status = 'revoked'; },
			(f: ReturnType<typeof fixture>) => { f.row.user_id = 'another-user'; },
		]) {
			const f = fixture(); change(f);
			await assert.rejects(authenticateJwt(f.repos, await token(), config), status(403));
		}
	});

	it('fails closed on invalid operator configuration', () => {
		const base = JSON.parse(config);
		for (const value of [null, {}, { ...base, algorithm: 'HS256' }, { ...base, audience: '' },
			{ ...base, jwksUrl: 'https://keys.test' }, { ...base, publicKey: undefined, jwksUrl: 'http://keys.test' },
			{ ...base, requiredScopes: 'ai:invoke' }, { ...base, typo: true }]) {
			assert.throws(() => parseJwtAuthConfig(JSON.stringify(value)), status(503));
		}
	});

	it('fetches only configured JWKS, caches it, rotates keys after cooldown, and fails closed on outage', async (t) => {
		const jwksConfig = JSON.stringify({ issuer, audience, algorithm: 'RS256', jwksUrl: 'https://keys.example.test/jwks' });
		const first = { ...await exportJWK(publicKey), kid: 'first', alg: 'RS256' };
		const secondPair = await generateKeyPair('RS256', { extractable: true });
		const second = { ...await exportJWK(secondPair.publicKey), kid: 'second', alg: 'RS256' };
		let keys = [first];
		let calls = 0;
		let unavailable = false;
		t.mock.method(globalThis, 'fetch', async (url: string) => {
			assert.equal(url, 'https://keys.example.test/jwks'); calls++;
			return new Response(unavailable ? 'offline' : JSON.stringify({ keys }), { status: unavailable ? 503 : 200 });
		});
		const jwt = await token({}, { kid: 'first', jku: 'https://attacker.test/jwks' });
		await authenticateJwt(fixture().repos, jwt, jwksConfig);
		await authenticateJwt(fixture().repos, jwt, jwksConfig);
		assert.equal(calls, 1);
		keys = [second];
		const next = await new SignJWT({ iss: issuer, aud: audience, sub: 'subject-1', exp: now() + 3600 })
			.setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'second' }).sign(secondPair.privateKey);
		await assert.rejects(authenticateJwt(fixture().repos, next, jwksConfig), status(401));
		const start = Date.now();
		t.mock.method(Date, 'now', () => start + 31_000);
		await authenticateJwt(fixture().repos, next, jwksConfig);
		assert.equal(calls, 2);
		unavailable = true;
		t.mock.method(Date, 'now', () => start + 700_000);
		await assert.rejects(authenticateJwt(fixture().repos, next, jwksConfig), status(503));
	});
});

describe('JWT through the shared gateway middleware', () => {
	function app(repos: GatewayRepositories) {
		const api = new Hono<Env>();
		api.use('*', async (c, next) => { c.set('repositories', repos); await next(); });
		api.use('*', requireApiKey);
		api.all('*', (c) => c.json(c.get('apiKey')!));
		return api;
	}
	it('supports Bearer JWT and existing API keys; disabled JWT does not fall back to key lookup', async () => {
		const { repos } = fixture();
		const api = app(repos);
		const jwt = await token();
		for (const credential of [jwt, 'sk-existing-key']) {
			const res = await api.request('/v1/me', { headers: { Authorization: `Bearer ${credential}` } }, { JWT_AUTH_CONFIG: config });
			assert.equal(res.status, 200);
			assert.equal((await res.json()).keyId, 'billing-key');
		}
		const denied = await api.request('/v1/me', { headers: { Authorization: `Bearer ${jwt}` } }, {});
		assert.equal(denied.status, 401);
		assert.ok(denied.headers.get('WWW-Authenticate'));
		const sdkHeader = await api.request('/v1/messages', { headers: { 'x-api-key': jwt } }, { JWT_AUTH_CONFIG: config });
		assert.equal(sdkHeader.status, 401);
	});
	it('retains budget enforcement and key/user rate limits', async () => {
		const f = fixture();
		f.row.budget_max = 0; f.row.wallet_granted = 0;
		const request = { method: 'POST', headers: { Authorization: `Bearer ${await token()}` } };
		assert.equal((await app(f.repos).request('/v1/responses', request, { JWT_AUTH_CONFIG: config })).status, 403);
		f.row.budget_max = 10;
		f.row.rate_limit = { rpm: 0 };
		assert.equal((await app(f.repos).request('/v1/responses', request, { JWT_AUTH_CONFIG: config })).status, 429);
		f.row.rate_limit = null; f.row.user_rate_limit = { rpm: 0 };
		assert.equal((await app(f.repos).request('/v1/responses', request, { JWT_AUTH_CONFIG: config })).status, 429);
	});
});
