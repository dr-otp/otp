import { Cache, CACHE_MANAGER } from '@nestjs/cache-manager';
import { HttpStatus, Inject, Injectable, Logger } from '@nestjs/common';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import * as crypto from 'crypto';
import { authenticator } from 'otplib';
import { firstValueFrom } from 'rxjs';
import { User } from 'src/common';
import { envs, NATS_SERVICE } from 'src/config';

@Injectable()
export class OtpService {
  private readonly logger = new Logger(OtpService.name);
  private readonly algorithm = 'aes-256-cbc'; // Encryption algorithm
  private readonly key = crypto.createHash('sha256').update(String(envs.otpSecret)).digest(); // Encryption key

  constructor(
    @Inject(CACHE_MANAGER) private readonly cacheManager: Cache,
    @Inject(NATS_SERVICE) private readonly client: ClientProxy,
  ) {}

  healthCheck(): string {
    return 'OTP service is up and running (งツ)ว';
  }

  async generateOtp(user: User) {
    try {
      // Generate
      const secret = authenticator.generateSecret();
      const token = authenticator.generate(secret);

      // Save
      const encryptedOtp = this.encrypt(token);
      await this.cacheManager.set(`otp:${user.email}`, encryptedOtp, envs.otpTtl);

      // Send OTP via email microservice
      try {
        await firstValueFrom(this.client.send('email.send.otp', { to: user.email, otp: token, username: user.username }));
      } catch (sendError) {
        this.logger.log('Error sending OTP via email microservice:', sendError);
        throw new RpcException({ status: HttpStatus.INTERNAL_SERVER_ERROR, message: 'Error sending OTP via email' });
      }

      return {
        message: `OTP sent to user: ${user.email}`,
        token,
      };
    } catch (error) {
      this.logger.log('🚀 ~ OtpService ~ generateOtp ~ error:', error);
      throw new RpcException({ status: HttpStatus.INTERNAL_SERVER_ERROR, message: 'Error generating OTP' });
    }
  }

  async verifyOtp(userEmail: string, otp: string) {
    this.logger.log(`Verifying OTP for user: ${userEmail}`);

    // Retrieve
    const storedOtp = await this.cacheManager.get<string>(`otp:${userEmail}`);

    if (!storedOtp) throw new RpcException({ status: HttpStatus.BAD_REQUEST, message: 'OTP Invalid or Expired' });

    // Encrypt the input OTP using the same key and IV
    const [encryptedOtp, iv] = storedOtp.split(':');
    const [encryptedInputOtp] = this.encrypt(otp, Buffer.from(iv, 'hex')).split(':');

    // Compare the encrypted OTPs
    const isValid = this.constantTimeComparison(encryptedOtp, encryptedInputOtp);

    if (!isValid) throw new RpcException({ status: HttpStatus.BAD_REQUEST, message: 'OTP Invalid or Expired' });

    return {
      message: 'OTP verified successfully',
    };
  }

  /**
   * Encrypts the provided OTP string using the specified algorithm and key.
   * The encrypted value is returned along with the initialization vector (IV) in hexadecimal format.
   *
   * @param {string} otp - The one-time password (OTP) string to be encrypted.
   * @param {Buffer} [iv=crypto.randomBytes(16)] - The initialization vector (IV) used for encryption. Defaults to a randomly generated 16-byte buffer.
   * @returns {string} The encrypted OTP concatenated with the IV, separated by a colon.
   */
  private encrypt(otp: string, iv: Buffer = crypto.randomBytes(16)): string {
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    let encrypted = cipher.update(otp, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${encrypted}:${iv.toString('hex')}`;
  }

  /**
   * Performs a constant-time comparison between two strings to prevent timing attacks.
   *
   * This function compares two strings for equality without leaking timing information
   * that could be used to guess the value of the strings. It ensures that the time taken
   * to compare the strings is the same regardless of where the first difference occurs.
   *
   * @param {string} val1 - The first string to compare.
   * @param {string} val2 - The second string to compare.
   * @returns {boolean} - Returns `true` if the strings are equal, `false` otherwise.
   *
   * @example
   * const isEqual = constantTimeComparison('abc123', 'abc123'); // true
   * const isEqual = constantTimeComparison('abc123', 'abc124'); // false
   */
  private constantTimeComparison(val1: string, val2: string): boolean {
    if (val1.length !== val2.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < val1.length; i++) {
      result |= val1.charCodeAt(i) ^ val2.charCodeAt(i);
    }

    return result === 0;
  }
}
