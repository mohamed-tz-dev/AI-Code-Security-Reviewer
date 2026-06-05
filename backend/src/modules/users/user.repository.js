const { pool } = require('../../db/pool');

async function createUser({ email, passwordHash, role }) {
  const result = await pool.query(
    `
      insert into users (email, password_hash, role)
      values ($1, $2, $3)
      returning id, email, role, created_at, last_login_at
    `,
    [email.toLowerCase(), passwordHash, role]
  );

  return result.rows[0];
}

async function findUserByEmail(email) {
  const result = await pool.query('select * from users where email = $1', [email.toLowerCase()]);
  return result.rows[0] || null;
}

async function findUserById(userId) {
  const result = await pool.query(
    'select id, email, role, created_at, last_login_at from users where id = $1',
    [userId]
  );
  return result.rows[0] || null;
}

async function markLogin(userId) {
  await pool.query('update users set last_login_at = now() where id = $1', [userId]);
}

async function listUsers() {
  const result = await pool.query(`
    select id, email, role, created_at, last_login_at
    from users
    order by created_at desc
    limit 100
  `);

  return result.rows;
}

async function updateUserRole(userId, role) {
  const result = await pool.query(
    `
      update users
      set role = $2
      where id = $1
      returning id, email, role, created_at, last_login_at
    `,
    [userId, role]
  );

  return result.rows[0] || null;
}

module.exports = {
  createUser,
  findUserByEmail,
  findUserById,
  listUsers,
  markLogin,
  updateUserRole
};
