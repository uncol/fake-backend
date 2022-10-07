import * as jwt from 'jsonwebtoken';

import { Config } from '../config';

export interface Tokens {
  access_token: string;
  expires_in: number;
  type: string;
}

export function TokensGenerator(
  username: string | jwt.JwtPayload | undefined,
  config: Config,
): Tokens {
  const access_token = jwt.sign({ sub: username }, config.secret_key, {
    expiresIn: config.access_token_expires_in,
  });
  return {
    access_token,
    expires_in: config.access_token_expires_in,
    type: 'bearer',
  };
}
