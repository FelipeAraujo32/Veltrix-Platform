import { CorrelationService } from '@veltrix/shared-client/services/correlation.service';

describe('CorrelationService (shared-client)', () => {
  it('creates a non-empty identifier', () => {
    const service = new CorrelationService();
    expect(service.create().length).toBeGreaterThan(10);
  });

  it('creates a different identifier on each call', () => {
    const service = new CorrelationService();
    expect(service.create()).not.toBe(service.create());
  });
});
