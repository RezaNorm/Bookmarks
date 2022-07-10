/* eslint-disable prettier/prettier */
import { Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaService } from '../prisma/prisma.service';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    // generate hashed password
    const password = await argon.hash(dto.password);

    // save and return user in the database
    return await this.prisma.user.create({
      data: {
        email: dto.email,
        password,
      },
    });

  }

  signin() {
    return `fuck you`;
  }
}
