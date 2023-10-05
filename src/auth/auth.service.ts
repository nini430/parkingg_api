import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';

import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(
    private config: ConfigService,
    private prisma: PrismaService,
    private jwt: JwtService,
  ) {}
  async hashData(data: string) {
    const hashed = await argon2.hash(data);
    return hashed;
  }
  async signTokens(userId: string, email: string): Promise<Tokens> {
    const payload = {
      sub: userId,
      email,
    };
    const [at, rt] = await Promise.all([
      this.jwt.signAsync(payload, {
        secret: this.config.get('JWT_ACCESS_TOKEN_SECRET'),
        expiresIn: this.config.get('JWT_ACCESS_TOKEN_EXPIRE_MIN'),
      }),
      this.jwt.signAsync(payload, {
        secret: this.config.get('JWT_REFRESH_TOKEN_SECRET'),
        expiresIn: this.config.get('JWT_REFRESH_TOKEN_EXPIRE_MIN'),
      }),
    ]);
    return {
      access_token: at,
      refresh_token: rt,
    };
  }
  async hashUserRrt(userId: string, rt: string) {
    const hashedRt = await this.hashData(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt,
      },
    });
  }
  async register(dto: RegisterDto): Promise<Tokens> {
    const hashedPassword = await this.hashData(dto.password);
    try {
      const newUser = await this.prisma.user.create({
        data: {
          ...dto,
          password: hashedPassword,
        },
      });
      const tokens = await this.signTokens(newUser.id, newUser.email);
      await this.hashUserRrt(newUser.id, tokens.refresh_token);
      console.log(tokens);
      return tokens;
    } catch (err) {
      console.log(err);
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('Credentials Taken');
        }
      }
    }
  }

  async login(dto: LoginDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) {
      throw new ForbiddenException('Invalid Credentials');
    }

    const pwdMatches = await argon2.verify(user.password, dto.password);
    if (!pwdMatches) {
      throw new ForbiddenException('Invalid Credentials');
    }

    const tokens = await this.signTokens(user.id, user.email);

    await this.hashUserRrt(user.id, tokens.refresh_token);
    return tokens;
  }
}
