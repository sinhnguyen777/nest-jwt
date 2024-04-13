import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor() {
    super({
      datasources: {
        db: {
          // url: configService.get<string>('DATABASE_URL'),
          url: 'postgres://nest_jwt_user:myCAvb7bC7ySoplLnpeL3m8pW7WyyLun@dpg-co2opusf7o1s73cn5ldg-a.singapore-postgres.render.com/nest_jwt',
        },
      },
    });
  }

  async onModuleInit() {
    await this.$connect();
  }
  async onModuleDestroy() {
    await this.$disconnect();
  }
}
