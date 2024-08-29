import { Module } from '@nestjs/common';
import { NatsModule } from 'src/transports/nats.module';
import { OtpController } from './otp.controller';
import { OtpService } from './otp.service';
import { RedisModule } from 'src/redis/redis.module';

@Module({
  controllers: [OtpController],
  providers: [OtpService],
  imports: [NatsModule, RedisModule],
})
export class OtpModule {}
