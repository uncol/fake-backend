export interface Config {
  secret_key: string;
  access_token_expires_in: string;
  refresh_token_expires_in: number;
}

export const PORT = process.env.PORT ?? 3000;
export const DATA_PATH =
  process.env.DATA_PATH ?? __dirname.slice(process.cwd().length + 1);
export const DATA_NAME = process.env.DATA_NAME ?? 'api.db.json';
export const JWT: Config = {
  secret_key: process.env.JWT_SECRET_KEY ?? 'SecretKey',
  access_token_expires_in: process.env.JWT_ACCESS_TOKEN_EXPIRES_IN ?? '1h',
  refresh_token_expires_in: Number(
    process.env.JWT_REFRESH_TOKEN_EXPIRES_IN ?? 60,
  ), // 2592000000 => 30 day
};
