import { IsEmail, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsNotEmpty()
  @IsOptional()
  @IsEmail()
  email: string;
  @IsString()
  @IsNotEmpty()
  @IsOptional()
  pId: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
