import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { Tedis } from 'tedis';

import { getConnection, revokeConnection } from '../utils/cache';
import { Tokens, TokensGenerator } from '../utils/generator';
import { JWT } from '../config';
import { getUsers } from './router';

const COOKIE_NAME = 'refreshToken';
const COOKIE_PATH = '/api/login';

export async function login(req, res) {
  const dbConnection = await getConnection();
  const payload: {
    username: string;
    password: string;
    grant_type: string;
    visitorId: string;
  } = {
    username: req.body.username,
    password: req.body.password,
    grant_type: req.body.grant_type,
    visitorId: req.body.visitorId,
  };

  switch (payload.grant_type) {
    case 'password': {
      const user: { id: number; username: string; password: string } | null =
        getUsers(payload.username, payload.password);
      if (user) {
        const newRefreshToken = uuidv4();
        const token = await cacheTokens(payload.username, payload.visitorId, dbConnection, newRefreshToken);
        res
          .status(200)
          .cookie(COOKIE_NAME, newRefreshToken, {
            httpOnly: true,
            path: COOKIE_PATH,
            maxAge: JWT.refresh_token_expires_in,
          })
          .json(token);
      } else {
        const status = 401;
        res
          .status(status)
          .json({ status, message: 'Incorrect username or password' });
      }
      break;
    }
    case 'refresh_token': {
      const newRefreshToken = uuidv4();
      const oldRefreshToken = req.cookies[COOKIE_NAME];
      let object: string | jwt.JwtPayload;

      try {
        await checkRefreshAndVisitorId(req, res, dbConnection);
        const accessToken = await dbConnection.hmget(
          oldRefreshToken,
          'accessToken',
        );
        if (accessToken && accessToken.length) {
          object = jwt.verify(accessToken[0], JWT.secret_key);
        }
        const username = await dbConnection.hmget(oldRefreshToken, 'username');
        if (username && username.length && object.sub !== username[0]) {
          const status = 401;
          res.status(status).json({ status, message: 'invalid username' });
          return;
        }
        const token = await cacheTokens(username[0], req.body.visitorId, dbConnection, newRefreshToken);
        res
          .status(200)
          .cookie(COOKIE_NAME, newRefreshToken, {
            httpOnly: true,
            path: COOKIE_PATH,
            maxAge: JWT.refresh_token_expires_in,
          })
          .json(token);
        await deleteToken(oldRefreshToken);
      } catch (error) {
        const status = error.status ?? 401;
        const message = error.message ?? 'invalid access_token';
        res.status(status).json({ status, message });
      }
      break;
    }
    default:
      break;
  }
  revokeConnection(dbConnection);
}

export async function revoke(req, res) {
  const dbConnection = await getConnection();
  try{
    await checkRefreshAndVisitorId(req, res, dbConnection);
    await deleteToken(req.cookies[COOKIE_NAME]);
    res.status(200).json({ message: 'Ok', status: true });
  } catch (error) {
    res.status(401).json(error);
  }
  finally {
    revokeConnection(dbConnection);
  }
}

export function isAuth(req, res) {
  const status = 200;
  const message = 'Ok';
  const payload: {
    access_token: string;
  } = {
    access_token: req.body.access_token,
  };
  try {
    jwt.verify(payload.access_token, JWT.secret_key);
    res.status(200).json({ status, message });
  } catch (err) {
    const status = 401;
    let message = 'Error verify access_token';

    if (err instanceof jwt.JsonWebTokenError) {
      message = err.message;
    }
    res.status(status).json({ status, message });
  }
}

async function checkRefreshAndVisitorId(req, res, dbConnection) {
  const oldRefreshToken = req.cookies[COOKIE_NAME];
  const payload: {
    visitorId: string;
  } = {
    visitorId: req.body.visitorId,
  };

  if (!oldRefreshToken) {
    throw { status: 401, message: 'refresh token must be provided' };
  }

  if (!(await dbConnection.exists(oldRefreshToken))) {
    throw { status: 401, message: 'invalid refresh token' };
  }
  const visitorId = await dbConnection.hmget(
      oldRefreshToken,
      'visitorId',
  );
  if (
      visitorId &&
      visitorId.length &&
      visitorId[0] !== payload.visitorId
  ) {
    const status = 401;
    throw { status, message: 'invalid visitorId' };
  }
}

async function deleteToken(refreshToken) {
  const dbConnection = await getConnection();
  const keys: string[] = await dbConnection.hkeys(refreshToken);

  for (const key of keys) {
    await dbConnection.hdel(refreshToken, key);
  }
  revokeConnection(dbConnection);
}

async function cacheTokens(username: string, visitorId: string, dbConnection: Tedis, newRefreshToken: string) {
  const token: Tokens = TokensGenerator(username, JWT);
  const data = {
    visitorId: visitorId ?? 'undefined',
    username: username ?? 'undefined',
    accessToken: token.access_token
  };

  await dbConnection.hmset(newRefreshToken, data);
  await dbConnection.expire(
      newRefreshToken,
      JWT.refresh_token_expires_in
  );
  return token;
}

