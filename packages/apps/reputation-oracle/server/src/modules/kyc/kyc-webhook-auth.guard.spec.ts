import { createHmac } from 'crypto';

import { createMock } from '@golevelup/ts-jest';
import { ExecutionContext, HttpException, HttpStatus } from '@nestjs/common';

import { KycConfigService } from '@/config';

import { KycWebhookAuthGuard } from './kyc-webhook-auth.guard';

const API_KEY = 'test-api-key';
const PRIVATE_KEY = 'test-private-key';

function contextFor(
  body: unknown,
  headers: Record<string, string | undefined>,
): ExecutionContext {
  return createMock<ExecutionContext>({
    switchToHttp: () => ({
      getRequest: () => ({ body, headers }),
    }),
  }) as ExecutionContext;
}

function sign(body: unknown): string {
  return createHmac('sha256', PRIVATE_KEY)
    .update(JSON.stringify(body))
    .digest('hex');
}

describe('KycWebhookAuthGuard', () => {
  let guard: KycWebhookAuthGuard;

  beforeEach(() => {
    const config = createMock<KycConfigService>();
    Object.defineProperty(config, 'apiKey', { get: () => API_KEY });
    Object.defineProperty(config, 'apiPrivateKey', { get: () => PRIVATE_KEY });
    guard = new KycWebhookAuthGuard(config);
  });

  const body = { status: 'approved', id: 'abc' };

  it('accepts a correctly signed request', () => {
    const context = contextFor(body, {
      'x-auth-client': API_KEY,
      'x-hmac-signature': sign(body),
    });

    expect(guard.canActivate(context)).toBe(true);
  });

  it('rejects a request with no signature', () => {
    const context = contextFor(body, { 'x-auth-client': API_KEY });

    expect(() => guard.canActivate(context)).toThrow(
      new HttpException('HMAC Signature not provided', HttpStatus.BAD_REQUEST),
    );
  });

  it('rejects a signature computed with the wrong key', () => {
    const wrong = createHmac('sha256', 'not-the-private-key')
      .update(JSON.stringify(body))
      .digest('hex');
    const context = contextFor(body, {
      'x-auth-client': API_KEY,
      'x-hmac-signature': wrong,
    });

    expect(() => guard.canActivate(context)).toThrow(HttpException);
  });

  it('rejects a signature for a different body', () => {
    const context = contextFor(body, {
      'x-auth-client': API_KEY,
      'x-hmac-signature': sign({ status: 'declined', id: 'abc' }),
    });

    expect(() => guard.canActivate(context)).toThrow(HttpException);
  });

  it('rejects a correct signature with the wrong api key', () => {
    const context = contextFor(body, {
      'x-auth-client': 'someone-elses-key',
      'x-hmac-signature': sign(body),
    });

    expect(() => guard.canActivate(context)).toThrow(HttpException);
  });

  /**
   * The signature and the api key arrive as headers, so express types them as
   * `string | string[]`. A repeated header must not be able to reach the
   * comparison.
   */
  it('rejects a repeated signature header', () => {
    const context = contextFor(body, {
      'x-auth-client': API_KEY,
      'x-hmac-signature': [sign(body), sign(body)] as unknown as string,
    });

    expect(() => guard.canActivate(context)).toThrow(HttpException);
  });
});
