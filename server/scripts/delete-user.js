#!/usr/bin/env node
import readline from 'node:readline'
import process from 'node:process'

function usage(exitCode = 0) {
  const msg = `Usage:
  node scripts/delete-user.js --username <name> [--yes] [--dry-run]

Options:
  --username, -u   Username to delete (exact match)
  --yes, -y        Skip confirmation prompt
  --dry-run        Print what would be deleted, but do not modify DB
  --help, -h       Show this help

Notes:
  - This performs the same DB deletion as Settings → Delete account (signedDeleteAccount).
  - If the main server process is running, any in-memory session/websocket state for the user may persist until restart.
`
  // eslint-disable-next-line no-console
  console.log(msg)
  process.exit(exitCode)
}

function parseArgs(argv) {
  const out = { username: null, yes: false, dryRun: false, help: false }

  for (let i = 2; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--help' || a === '-h') out.help = true
    else if (a === '--yes' || a === '-y') out.yes = true
    else if (a === '--dry-run') out.dryRun = true
    else if (a === '--username' || a === '-u') {
      out.username = String(argv[i + 1] ?? '')
      i++
    } else if (!a.startsWith('-') && !out.username) {
      // Allow positional username as convenience
      out.username = String(a)
    } else {
      return { ...out, help: true }
    }
  }

  return out
}

async function promptConfirm(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  try {
    const answer = await new Promise((resolve) => rl.question(question, resolve))
    return String(answer).trim().toLowerCase() === 'yes'
  } finally {
    rl.close()
  }
}

async function main() {
  const args = parseArgs(process.argv)
  if (args.help) usage(0)

  const username = String(args.username ?? '').trim()
  if (!username) usage(1)

  const { initDatabase, query, getPool } = await import('../db.js')
  const { signedDeleteAccount } = await import('../signedDb.js')

  initDatabase()

  const r = await query('SELECT id, username, remove_date FROM users WHERE username = $1', [username])
  if (!r.rowCount) {
    // eslint-disable-next-line no-console
    console.error(`User not found: ${username}`)
    process.exit(2)
  }

  const row = r.rows[0]
  const userId = String(row.id)

  // eslint-disable-next-line no-console
  console.log(`Target: username=${row.username} id=${userId} remove_date=${row.remove_date}`)

  if (args.dryRun) {
    // eslint-disable-next-line no-console
    console.log('[dry-run] Would delete user and cascade related rows; would also prune orphaned chats.')
    process.exit(0)
  }

  if (!args.yes) {
    const ok = await promptConfirm(`Type 'yes' to permanently delete this user: `)
    if (!ok) {
      // eslint-disable-next-line no-console
      console.log('Aborted.')
      process.exit(0)
    }
  }

  const res = await signedDeleteAccount(userId)

  // eslint-disable-next-line no-console
  console.log(`Deleted users: ${res.deletedUsers}; deleted chats: ${res.deletedChats}`)

  // Close DB pool so the process exits promptly.
  try {
    await getPool().end()
  } catch {
    // ignore
  }
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error('Failed to delete user:', e?.message ?? e)
  process.exit(1)
})
