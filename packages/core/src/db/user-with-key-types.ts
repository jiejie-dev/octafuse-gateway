import type { UserRow } from '../types';
import type { InsertKeyParams } from './api-keys-types';
import type { InsertUserAuditLogParams } from './user-audit-logs-types';

/** Insert-only atomic provisioning; uniqueness conflicts must roll back every row. */
export type CreateUserWithKeyParams = {
	user: UserRow;
	key: InsertKeyParams;
	audits: InsertUserAuditLogParams[];
};
