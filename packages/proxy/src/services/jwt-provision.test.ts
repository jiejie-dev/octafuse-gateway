import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { after, before, describe, it } from 'node:test';
import { Miniflare } from 'miniflare';
import { exportSPKI, generateKeyPair, SignJWT } from 'jose';
import { createD1StorageContext, type GatewayRepositories } from '@octafuse/core';
import { authenticateJwt, JwtAuthError, parseJwtAuthConfig } from './jwt-auth';

describe('JWT automatic enrollment with real D1 transactions', () => {
	let mf: Miniflare;
	let repos: GatewayRepositories;
	let db: Awaited<ReturnType<Miniflare['getD1Database']>>;
	let privateKey: CryptoKey;
	let config: string;
	const issuer = 'https://auth.example.test';
	before(async () => {
		mf = new Miniflare({ modules: true, script: 'export default { fetch() { return new Response("ok") } }',
			compatibilityDate: '2025-04-01', d1Databases: ['DB'] });
		db = await mf.getD1Database('DB');
		const migrations = new URL('../../../core/migrations-d1/', import.meta.url);
		for (const filename of (await readdir(migrations)).filter((name) => name.endsWith('.sql')).sort()) {
			const sql = await readFile(new URL(filename, migrations), 'utf8');
			// D1 exec expects each statement on one line; migration SQL has no procedural blocks.
			for (const statement of sql.replace(/--[^\n]*/g, '').split(';').map((part) => part.trim()).filter(Boolean)) {
				await db.prepare(statement).run();
			}
		}
		repos = createD1StorageContext(db).repositories;
		const pair = await generateKeyPair('RS256', { extractable: true });
		privateKey = pair.privateKey;
		config = JSON.stringify({ issuer, audience: 'gateway', algorithm: 'RS256', publicKey: await exportSPKI(pair.publicKey),
			requiredScopes: ['ai:invoke'], autoProvision: { budgetMax: 10, budgetPeriod: 'monthly', rpm: 60 } });
	});
	after(async () => { await mf?.dispose(); });

	function token(sub: string, claims: Record<string, unknown> = {}) {
		return new SignJWT({ iss: issuer, aud: 'gateway', sub, exp: Math.floor(Date.now() / 1000) + 3600,
			scope: 'ai:invoke', ...claims }).setProtectedHeader({ alg: 'RS256', typ: 'at+jwt' }).sign(privateKey);
	}
	function status(expected: number) {
		return (error: unknown) => error instanceof JwtAuthError && error.status === expected;
	}
	it('creates one user, key and audit pair under simultaneous first requests', async () => {
		const jwt = await token('concurrent');
		const results = await Promise.all(Array.from({ length: 12 }, () => authenticateJwt(repos, jwt, config)));
		assert.equal(new Set(results.map((result) => result.userId)).size, 1);
		assert.equal(new Set(results.map((result) => result.keyId)).size, 1);
		const result = results[0]!;
		assert.equal(result.budgetMax, 10);
		assert.equal(result.budgetSpent, 0);
		assert.equal(result.budgetPeriod, 'monthly');
		assert.ok(result.budgetResetAt);
		assert.deepEqual(result.userRateLimit, { rpm: 60 });
		const keys = await repos.apiKeys.listKeysByUserId(result.userId);
		assert.equal(keys.length, 1);
		assert.equal(keys[0].id, result.keyId);
		const count = await db.prepare('SELECT count(*) AS n FROM user_audit_logs WHERE user_id = ?').bind(result.userId).first('n');
		assert.equal(count, 2);
		// Failed racing transactions must not leave orphan users or keys.
		assert.equal(await db.prepare('SELECT count(*) AS n FROM users').first('n'), 1);
		assert.equal(await db.prepare('SELECT count(*) AS n FROM api_keys').first('n'), 1);
	});

	it('does not refill budget or overwrite administrative settings on subsequent tokens', async () => {
		const initial = await authenticateJwt(repos, await token('returning'), config);
		await db.prepare('UPDATE users SET budget_spent = 4, rate_limit = ? WHERE id = ?')
			.bind('{"rpm":7}', initial.userId).run();
		const changedPolicy = JSON.stringify({ ...JSON.parse(config), autoProvision: { budgetMax: 1000, rpm: null } });
		const next = await authenticateJwt(repos, await token('returning'), changedPolicy);
		assert.equal(next.userId, initial.userId);
		assert.equal(next.keyId, initial.keyId);
		assert.equal(next.budgetMax, 10);
		assert.equal(next.budgetSpent, 4);
		assert.deepEqual(next.userRateLimit, { rpm: 7 });
	});

	it('supports an explicit unlimited budget and does not require or merge email claims', async () => {
		const unlimited = JSON.stringify({ ...JSON.parse(config), autoProvision: { budgetMax: null, rpm: null } });
		const first = await authenticateJwt(repos, await token('no-email'), unlimited);
		assert.equal(first.budgetMax, null);
		assert.equal(first.userRateLimit, null);
		assert.match(first.userEmail!, /^[a-f0-9]{64}@jwt\.invalid$/);
		const a = await authenticateJwt(repos, await token('email-a', { email: 'shared@example.test' }), config);
		const b = await authenticateJwt(repos, await token('email-b', { email: 'shared@example.test' }), config);
		assert.notEqual(a.userId, b.userId);
		assert.notEqual(a.userEmail, b.userEmail);
	});

	it('does not auto-enable disabled users or replace revoked/deleted billing bindings', async () => {
		for (const action of ['disable', 'revoke', 'unbind']) {
			const jwt = await token(action);
			const initial = await authenticateJwt(repos, jwt, config);
			if (action === 'disable') await repos.users.updateUserStatus(initial.userId, 'disabled');
			if (action === 'revoke') await repos.apiKeys.revokeApiKey(initial.keyId);
			if (action === 'unbind') await repos.users.setUserMetadataById(initial.userId, '{}');
			await assert.rejects(authenticateJwt(repos, jwt, config), status(403));
			assert.equal((await repos.apiKeys.listKeysByUserId(initial.userId)).length, 1);
		}
	});

	it('never provisions invalid or insufficient-scope tokens; manual mode still rejects unknown users', async () => {
		await assert.rejects(authenticateJwt(repos, await token('invalid', { aud: 'wrong' }), config), status(401));
		await assert.rejects(authenticateJwt(repos, await token('scope', { scope: '' }), config), status(403));
		const manual = { ...JSON.parse(config) }; delete manual.autoProvision;
		await assert.rejects(authenticateJwt(repos, await token('manual'), JSON.stringify(manual)), status(403));
		for (const subject of ['invalid', 'scope', 'manual']) assert.equal(await repos.users.getByExternalPair(issuer, subject), null);
	});

	it('rolls back a provisioning failure and can retry without granting twice', async () => {
		await db.prepare(`CREATE TRIGGER reject_jwt_key BEFORE INSERT ON api_keys BEGIN SELECT RAISE(ABORT, 'test failure'); END`).run();
		const jwt = await token('retry');
		try {
			await assert.rejects(authenticateJwt(repos, jwt, config), status(503));
			assert.equal(await repos.users.getByExternalPair(issuer, 'retry'), null);
		} finally {
			await db.prepare('DROP TRIGGER reject_jwt_key').run();
		}
		const result = await authenticateJwt(repos, jwt, config);
		assert.equal(result.budgetMax, 10);
		assert.equal((await repos.apiKeys.listKeysByUserId(result.userId)).length, 1);
	});

	it('validates explicit enrollment defaults, including unlimited and zero allowances', () => {
		assert.deepEqual(parseJwtAuthConfig(JSON.stringify({ ...JSON.parse(config), autoProvision: { budgetMax: 0 } })).autoProvision,
			{ budgetMax: 0, budgetPeriod: 'none', rpm: 60 });
		for (const policy of [true, {}, { budgetMax: -1 }, { budgetMax: '10' }, { budgetMax: 1e13 },
			{ budgetMax: 10, budgetPeriod: 'yearly' }, { budgetMax: 10, rpm: -1 }, { budgetMax: 10, rpm: 0.5 }]) {
			assert.throws(() => parseJwtAuthConfig(JSON.stringify({ ...JSON.parse(config), autoProvision: policy })), status(503));
		}
	});
});
