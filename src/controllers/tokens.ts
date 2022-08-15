import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

import { getConnection, revokeConnection } from '../utils/cache';
import { TokensGenerator } from '../utils/generator';
import { JWT } from '../config';
import { getUsers } from './router';

export async function login(req, res) {
  const COOKIE_NAME = 'refreshToken';
  const dbConnection = await getConnection();
  const payload: {
    username: string;
    password: string;
    grant_type: string;
    refresh_token: string;
    visitorId: string;
  } = {
    username: req.body.username,
    password: req.body.password,
    refresh_token: req.body.refresh_token,
    grant_type: req.body.grant_type,
    visitorId: req.body.visitorId,
  };

  switch (payload.grant_type) {
    case 'password': {
      const user: { id: number; username: string; password: string } | null = getUsers(payload.username, payload.password);

      if (user) {
        const newRefreshToken = uuidv4();
        const data = {
          visitorId: payload.visitorId ?? 'undefined',
          username: payload.username ?? 'undefined',
        };

        await dbConnection.hmset(newRefreshToken, data);
        await dbConnection.expire(newRefreshToken, JWT.refresh_token_expires_in);
        res
          .status(200)
          .cookie(COOKIE_NAME, newRefreshToken, {
            httpOnly: true,
            path: '/api/login',
            maxAge: JWT.refresh_token_expires_in,
          })
          .json(TokensGenerator(user.username, JWT));
      } else {
        const status = 401;
        const message = 'Incorrect username or password';
        res.status(status).json({ status, message });
      }
      break;
    }
    case 'refresh_token': {
      const newRefreshToken = uuidv4();
      const oldRefreshToken = req.cookies[COOKIE_NAME];
      let object: string | jwt.JwtPayload;

      try {
        object = jwt.verify(payload.refresh_token, JWT.secret_key);
        res
          .status(200)
          .cookie(COOKIE_NAME, newRefreshToken, {
            httpOnly: true,
            path: '/api/login',
            maxAge: JWT.refresh_token_expires_in,
          })
          .json(TokensGenerator(object.sub, JWT));
      } catch (error) {
        const status = 401;
        const message = 'Error invalid access_token';
        res.status(status).json({ status, message });
      }
      break;
    }
    default:
      break;
  }
  revokeConnection(dbConnection);
}

export function revoke(req, res) {
  res.status(200).json({ message: 'Ok', status: true });
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
