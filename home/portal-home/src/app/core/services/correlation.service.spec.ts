import { TestBed } from '@angular/core/testing';
import { CorrelationService } from '@veltrix/shared-client/services/correlation.service';

describe('CorrelationService', () => {
  it('creates a different non-empty identifier for each request', () => {
    const service = TestBed.inject(CorrelationService);
    const first = service.create();
    const second = service.create();
    expect(first.length).toBeGreaterThan(10);
    expect(second).not.toBe(first);
  });
});
