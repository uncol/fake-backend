import { router as jsonRouter } from 'json-server';
import { join } from 'path';
import { DATA_NAME, DATA_PATH } from '../config';

export const router = jsonRouter(join(DATA_PATH, DATA_NAME));

export function getUsers(username, password) {
  return (
    (router.db.get('users') as any)
      .find({ username: username, password: password })
      .value() ?? null
  );
}
