import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';

const PORT = 8800

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  await app.listen(PORT);

  console.log(`Application is running on ${PORT}`)
}
bootstrap();
