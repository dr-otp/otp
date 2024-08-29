import { Type } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsNumberString, IsUUID } from 'class-validator';

export class VerifyOtpDto {
  @IsNotEmpty()
  @IsUUID()
  @Type(() => String)
  userId: string;

  @IsNotEmpty()
  @IsEmail()
  userEmail: string;

  @IsNumberString()
  @Type(() => String)
  otp: string;
}
