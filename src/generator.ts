import * as jwt from 'jsonwebtoken';

import { config } from './server';

export function TokensGenerator(username: string | jwt.JwtPayload | undefined, config: config) {
    const access_token = jwt.sign({sub: username}, config.secret_key, {
        expiresIn: config.access_token_expires_in
    });
    return {
        access_token,
        refresh_token: access_token,
        expires_in: config.access_token_expires_in,
        token_type: 'bearer'
    };
}
