import {
	computeFirstReset, createUserWithKey, roundGatewayMoney, snapshotToJson, userRowToSnapshot,
	type BudgetPeriod, type GatewayRepositories, type UserRow,
} from '@octafuse/core';

export type JwtAutoProvision = {
	/** Explicit null means unlimited; zero creates users without paid usage allowance. */
	budgetMax: number | null;
	budgetPeriod: BudgetPeriod;
	/** User-wide requests per minute. Null means unlimited. */
	rpm: number | null;
};

/** Called only after signature, claim and scope validation. Never changes an existing account. */
export async function provisionJwtUser(
	repos: GatewayRepositories,
	issuer: string,
	subject: string,
	policy: JwtAutoProvision,
): Promise<UserRow> {
	// A stable placeholder avoids requiring an email claim or colliding on shared email addresses.
	// Identity is always the original issuer + subject; no token-provided metadata is copied.
	const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify([issuer, subject])));
	const identity = Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, '0')).join('');
	const keyId = crypto.randomUUID();
	const secret = Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) => byte.toString(16).padStart(2, '0')).join('');
	const now = new Date().toISOString();
	const budget = policy.budgetMax == null ? null : roundGatewayMoney(policy.budgetMax);
	const user: UserRow = {
		id: crypto.randomUUID(), email: `${identity}@jwt.invalid`,
		external_system: issuer, external_user_id: subject, status: 'active',
		metadata: JSON.stringify({ jwt_api_key_id: keyId }),
		budget_max: budget, budget_base: budget ?? 0, budget_spent: 0,
		budget_period: policy.budgetPeriod,
		budget_reset_at: policy.budgetPeriod === 'none' ? null : computeFirstReset(policy.budgetPeriod),
		wallet_granted: 0, wallet_spent: 0, rate_limit: policy.rpm == null ? null : { rpm: policy.rpm },
		charged_cost_factors: null, created_at: now, updated_at: now,
	};
	const snapshot = snapshotToJson(userRowToSnapshot(user));
	const correlationId = crypto.randomUUID();
	try {
		await createUserWithKey(repos, {
			user,
			key: { id: keyId, key: `sk-${secret}`, userId: user.id, status: 'active', name: 'OAuth JWT billing' },
			audits: [
				{
					id: crypto.randomUUID(), userId: user.id, eventType: 'user_created', actorType: 'service',
					actorId: 'service:jwt_auto_provision', source: 'gateway_user_provision', reasonCode: 'user_provision_external',
					reasonText: 'User automatically provisioned from verified JWT', afterUserSnapshot: snapshot, correlationId,
				},
				{
					id: crypto.randomUUID(), userId: user.id, apiKeyId: keyId, eventType: 'key_created', actorType: 'service',
					actorId: 'service:jwt_auto_provision', source: 'key_provision', reasonCode: 'key_create',
					reasonText: 'JWT billing key automatically provisioned', beforeUserSnapshot: snapshot,
					afterUserSnapshot: snapshot, correlationId,
				},
			],
		});
	} catch (error) {
		// Concurrent first requests race on the existing unique external identity constraint.
		// Re-read only after rollback, outside the failed SQL transaction. Do not swallow outages.
		const winner = await repos.users.getByExternalPair(issuer, subject);
		if (winner) return winner;
		throw error;
	}
	// Re-read state so a concurrent admin disable/rebind is not undone by the initial snapshot.
	const created = await repos.users.getByExternalPair(issuer, subject);
	if (!created) throw new Error('JWT user provisioning could not be read back');
	return created;
}
