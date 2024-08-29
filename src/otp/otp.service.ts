import { Cache, CACHE_MANAGER } from '@nestjs/cache-manager';
import { HttpStatus, Inject, Injectable, Logger } from '@nestjs/common';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'crypto';
import { authenticator } from 'otplib';
import { firstValueFrom } from 'rxjs';
import { User } from 'src/common';
import { envs, NATS_SERVICE } from 'src/config';

@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name);
  private readonly algorithm = 'aes-256-ctr';

  constructor(
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    @Inject(NATS_SERVICE) private readonly client: ClientProxy,
  ) {}

  healthCheck(): string {
    return 'OTP service is up and running (งツ)ว';
  }

  async generateOtp(user: User) {
    this.logger.log(`Generating OTP for user: ${user.email}`);

    // Generate
    const secret = authenticator.generateSecret();
    const token = authenticator.generate(secret);
    this.logger.log(`Generated OTP: ${token}`);

    // Save
    const encryptedOtp = this.encrypt(secret);
    await this.cacheManager.set(`otp:${user.email}`, encryptedOtp, envs.otpTtl);

    // Send OTP via email microservice
    try {
      await firstValueFrom(
        this.client.send('email.send.otp', {
          to: user.email,
          otp: token,
          username: user.username,
        }),
      );
      this.logger.log(`OTP sent to user: ${user.email}`);
    } catch (sendError) {
      this.logger.log('Error sending OTP via email microservice:', sendError);
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid credentials',
      });
    }

    return {
      message: `OTP sent to user: ${user.email}`,
      token,
    };
  }

  private encrypt(text: string): string {
    const key = createHash('sha256').update(String(envs.otpSecret)).digest('base64').substring(0, 32);
    const iv = randomBytes(16);
    const cipher = createCipheriv(this.algorithm, Buffer.from(key), iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
    return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
  }

  private decrypt(text: string): string {
    const key = createHash('sha256').update(String(envs.otpSecret)).digest('base64').substring(0, 32);
    const [iv, encryptedText] = text.split(':');
    const decipher = createDecipheriv(this.algorithm, Buffer.from(key), Buffer.from(iv, 'hex'));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedText, 'hex')), decipher.final()]);
    return decrypted.toString();
  }
}
