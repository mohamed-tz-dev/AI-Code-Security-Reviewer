require('dotenv').config();

const fs = require('fs/promises');
const path = require('path');
const { pool } = require('./pool');

async function ensureMigrationsTable(client) {
  await client.query(`
    create table if not exists schema_migrations (
      id text primary key,
      applied_at timestamptz not null default now()
    )
  `);
}

async function migrate() {
  const migrationsDir = path.resolve(__dirname, 'migrations');
  const files = (await fs.readdir(migrationsDir))
    .filter((file) => file.endsWith('.sql'))
    .sort();

  const client = await pool.connect();

  try {
    await client.query('begin');
    await ensureMigrationsTable(client);

    for (const file of files) {
      const alreadyApplied = await client.query(
        'select id from schema_migrations where id = $1',
        [file]
      );

      if (alreadyApplied.rowCount > 0) {
        continue;
      }

      const sql = await fs.readFile(path.join(migrationsDir, file), 'utf8');
      await client.query(sql);
      await client.query('insert into schema_migrations (id) values ($1)', [file]);
      console.log(`Applied migration ${file}`);
    }

    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

migrate().catch((error) => {
  console.error('Migration failed:', error);
  process.exit(1);
});
