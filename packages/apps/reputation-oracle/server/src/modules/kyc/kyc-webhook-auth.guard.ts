import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { Request } from 'express';

import { KycConfigService } from '@/config';

/**
 * Per-process key used only to length-normalise the two values before they are
 * compared. Hashing both sides keeps the buffers the same size, so
 * timingSafeEqual never throws on a length mismatch and the expected value's
 * length is not observable from response timing either.
 */
const COMPARE_KEY = randomBytes(32);

function secretEquals(presented: string, expected: string): boolean {
  const left = createHmac('sha256', COMPARE_KEY).update(presented).digest();
  const right = createHmac('sha256', COMPARE_KEY).update(expected).digest();
  return timingSafeEqual(left, right);
}

@Injectable()
export class KycWebhookAuthGuard implements CanActivate {
  constructor(private readonly kycConfigService: KycConfigService) {}
  canActivate(context: ExecutionContext): boolean {
    const request: Request = context.switchToHttp().getRequest();

    const { headers, body } = request;
    const apiKey = headers['x-auth-client'];
    const hmacSignature = headers['x-hmac-signature'];

    if (!hmacSignature) {
      throw new HttpException(
        'HMAC Signature not provided',
        HttpStatus.BAD_REQUEST,
      );
    }

    const signedPayload = createHmac(
      'sha256',
      this.kycConfigService.apiPrivateKey,
    )
      .update(JSON.stringify(body))
      .digest('hex');

    if (
      typeof hmacSignature !== 'string' ||
      typeof apiKey !== 'string' ||
      !secretEquals(hmacSignature, signedPayload) ||
      !secretEquals(apiKey, this.kycConfigService.apiKey)
    ) {
      throw new HttpException(
        'HMAC Signature does not match',
        HttpStatus.UNAUTHORIZED,
      );
    }

    return true;
  }
}
