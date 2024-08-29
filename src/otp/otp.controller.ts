import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { OtpService } from './otp.service';
import { User } from 'src/common';

@Controller()
export class OtpController {
  constructor(private readonly otpService: OtpService) {}

  @MessagePattern('otp.health')
  healthCheck(): string {
    return this.otpService.healthCheck();
  }

  @MessagePattern('otp.generate')
  generateOtp(@Payload() payload: { user: User }) {
    const { user } = payload;
    return this.otpService.generateOtp(user);
  }
}
