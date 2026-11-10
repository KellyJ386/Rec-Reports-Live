#!/usr/bin/env node
// Creates local login accounts for the mock people in supabase/seed.sql.
//
// For every person with an email (in the seeded database), this:
//   1. creates a confirmed auth user through the Admin API. A user that already exists
//      with that email is NOT linked unless it is email-confirmed AND --link-existing is
//      passed (an outsider could have registered that email first); skipped users are listed;
//   2. inserts the matching public.accounts row (organization + person -> user),
//      skipping any person or user that already has one.
//
// Run after `scripts/db/test-local.sh --seed` (or the Supabase local stack with
// `supabase db reset`). It is idempotent.
//
// Environment (all required; nothing is read from files, nothing is printed):
//   NEXT_PUBLIC_SUPABASE_URL      e.g. http://127.0.0.1:54321
//   SUPABASE_SERVICE_ROLE_KEY     service role key of that project (never commit it)
//   MOCK_USER_PASSWORD            password given to every mock user
//
// Refuses to run unless the URL is localhost, or --i-know-this-is-not-production is passed.
//
//   node scripts/seed-users.mjs
//   node scripts/seed-users.mjs --i-know-this-is-not-production   (any other URL)
//   node scripts/seed-users.mjs --link-existing   (link confirmed users that already exist)

import { createClient } from '@supabase/supabase-js';
import { canLinkExistingUser } from './seed-users-guard.mjs';

const REQUIRED = ['NEXT_PUBLIC_SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'MOCK_USER_PASSWORD'];
const FLAG = '--i-know-this-is-not-production';
const LINK_EXISTING = process.argv.includes('--link-existing');

function fail(message) {
  console.error(`seed-users: ${message}`);
  process.exit(1);
}

const missing = REQUIRED.filter((name) => !process.env[name]);
if (missing.length > 0) {
  fail(`missing environment variable(s): ${missing.join(', ')}. Set them and run again.`);
}

const url = new URL(process.env.NEXT_PUBLIC_SUPABASE_URL);
const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
if (!isLocal && !process.argv.includes(FLAG)) {
  fail(
    `refusing to seed users into ${url.origin}: it is not localhost. ` +
      `Pass ${FLAG} only if you are certain this is not production.`,
  );
}

const admin = createClient(url.origin, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// Find an existing auth user by email (the Admin API has no lookup-by-email call).
async function findAuthUserByEmail(email) {
  for (let page = 1; ; page += 1) {
    const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 200 });
    if (error) throw error;
    const hit = data.users.find((u) => u.email?.toLowerCase() === email.toLowerCase());
    if (hit) return hit;
    if (data.users.length < 200) return null;
  }
}

async function ensureAuthUser(email) {
  const { data, error } = await admin.auth.admin.createUser({
    email,
    password: process.env.MOCK_USER_PASSWORD,
    email_confirm: true,
  });
  if (!error) return { user: data.user, created: true };
  // Already registered: link it only when it is confirmed and --link-existing was passed.
  // Any other error stops the run.
  const existing = await findAuthUserByEmail(email);
  if (!existing) throw error;
  const decision = canLinkExistingUser(existing, LINK_EXISTING);
  if (!decision.link) return { user: null, created: false, skipped: decision.reason };
  return { user: existing, created: false };
}

const { data: people, error: peopleError } = await admin
  .from('people')
  .select('id, organization_id, email')
  .not('email', 'is', null)
  .is('archived_at', null)
  .order('organization_id')
  .order('email');
if (peopleError) fail(`could not read people: ${peopleError.message}`);

const stats = { authCreated: 0, authReused: 0, accountCreated: 0, accountSkipped: 0 };
const skippedUsers = [];

for (const person of people) {
  const { user, created, skipped } = await ensureAuthUser(person.email);
  if (!user) {
    skippedUsers.push(`${person.email} (${skipped})`);
    continue;
  }
  if (created) stats.authCreated++;
  else stats.authReused++;

  const { data: existing, error: lookupError } = await admin
    .from('accounts')
    .select('id')
    .or(
      `person_id.eq.${person.id},and(user_id.eq.${user.id},organization_id.eq.${person.organization_id})`,
    )
    .limit(1);
  if (lookupError) fail(`could not read accounts: ${lookupError.message}`);
  if (existing.length > 0) {
    stats.accountSkipped++;
    continue;
  }

  const { error: insertError } = await admin.from('accounts').insert({
    organization_id: person.organization_id,
    person_id: person.id,
    user_id: user.id,
  });
  if (insertError) fail(`could not create account for person ${person.id}: ${insertError.message}`);
  stats.accountCreated++;
}

console.log(
  `seed-users: ${people.length} people; auth users created ${stats.authCreated}, reused ${stats.authReused}; ` +
    `accounts created ${stats.accountCreated}, already present ${stats.accountSkipped}.`,
);
if (skippedUsers.length > 0) {
  console.log(`seed-users: skipped ${skippedUsers.length} existing user(s), not linked:`);
  for (const line of skippedUsers) console.log(`  - ${line}`);
}
