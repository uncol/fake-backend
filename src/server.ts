import dotenv from 'dotenv';
import fs from 'fs';

if (fs.existsSync('.env')) {
  dotenv.config({ path: '.env' });
}

import * as bodyParser from 'body-parser';

import * as cookieParser from 'cookie-parser';
import { create, defaults, rewriter } from 'json-server';

import { PORT } from './config';
import { router } from './controllers/router';
import { isAuth, login, revoke } from './controllers/tokens';
import { checkAuth } from './middleware/auth';
import { initPool } from './utils/cache';

const server = create();
const middlewares = defaults();

initPool();
server.use(rewriter({
  "/api/data/*": "/$1"
}))
server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(cookieParser.default());
server.use(middlewares);

server.post('/api/login/token', login);
server.post('/api/login/revoke', revoke);
server.post('/api/login/is_login', isAuth);

server.use(/^(?!\/auth).*$/, checkAuth());
server.use(router);

server.listen(PORT, () => {
  console.log(`JSON Server is running on port: ${PORT}`);
});
