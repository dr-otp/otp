import 'dotenv/config';
import joi from 'joi';

interface EnvVars {
  PORT: number;
  NATS_SERVERS: string[];
  REDIS_URL: string;
  CACHE_TTL: number;
  REDIS_DB: number;
  OTP_SECRET: string;
  OTP_TTL: number;
}

const envSchema = joi
  .object({
    PORT: joi.number().required(),
    NATS_SERVERS: joi.array().items(joi.string()).required(),
    REDIS_URL: joi.string().required(),
    CACHE_TTL: joi.number().required(),
    REDIS_DB: joi.number().required(),
    OTP_SECRET: joi.string().required(),
    OTP_TTL: joi.number().required(), // 5 minutes
  })
  .unknown(true);

const { error, value } = envSchema.validate({ ...process.env, NATS_SERVERS: process.env.NATS_SERVERS?.split(',') });

if (error) throw new Error(`Config validation error: ${error.message}`);

const envVars: EnvVars = value;

export const envs = {
  port: envVars.PORT,
  natsServers: envVars.NATS_SERVERS,
  redisUrl: envVars.REDIS_URL,
  cacheTtl: envVars.CACHE_TTL,
  redisDb: envVars.REDIS_DB,
  otpSecret: envVars.OTP_SECRET,
  otpTtl: envVars.OTP_TTL,
};
