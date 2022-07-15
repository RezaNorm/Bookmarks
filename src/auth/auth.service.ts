/* eslint-disable prettier/prettier */
import { ForbiddenException, Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import {
  PrismaClientInitializationError,
  PrismaClientKnownRequestError,
} from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto) {
    // generate hashed password
    const password = await argon.hash(dto.password);

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          password,
        },
        select: {
          id: true,
          email: true,
          createdAt: true,
        },
      });
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials already exist');
        }
      }
    }
    // save and return user in the database
  }

  async signin(dto: AuthDto) {
    // find the user w/ entered credentials
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Wrong Credentials');

    // compared the entered password
    const passCompared = await argon.verify(user.password, dto.password);
    // delete user['password'];

    if (!passCompared) throw new ForbiddenException('Wrong Credentials');
    return this.signToken(user.id, user.email);
  }

  signToken(userId: Number, email: String): Promise<string> {
    const data = {
      sub: userId,
      email,
    };

    return this.jwt.signAsync(data, {
      expiresIn: '15m',
      secret: this.config.get<string>('JWT_SECRET'),
    });
  }
}
