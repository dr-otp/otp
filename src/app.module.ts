import { Module } from '@nestjs/common';
import { OtpModule } from './otp/otp.module';
import { RedisModule } from './redis/redis.module';

@Module({
  imports: [RedisModule, OtpModule],
})
export class AppModule {}
