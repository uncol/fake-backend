import { TedisPool } from 'tedis';

let _pool;

export function initPool() {
  if (!_pool) {
    _pool = new TedisPool({
      host: process.env.REDIS_HOST || '127.0.0.1',
      port: Number(process.env.REDIS_PORT) || 6379,
    });
  }
}

export function getConnection() {
  return _pool.getTedis();
}

export function revokeConnection(connection) {
  _pool.putTedis(connection);
}
