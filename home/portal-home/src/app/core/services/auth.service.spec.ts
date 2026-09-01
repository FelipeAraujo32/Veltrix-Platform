import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { AuthService } from '@veltrix/shared-client/services/auth.service';

const SESSION_MARKER = 'veltrix.session';

function jwt(claims: Record<string, unknown> = {}): string {
  const payload = btoa(JSON.stringify({ sub: '7', contexts: ['DEFAULT'], exp: Math.floor(Date.now() / 1000) + 300, ...claims }));
  return `header.${payload}.signature`;
}

describe('AuthService', () => {
  let service: AuthService;
  let http: HttpTestingController;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()] });
    service = TestBed.inject(AuthService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('keeps authorization claims in memory after login', () => {
    const token = jwt({ permissions: ['BILLING_READ'] });
    service.login('operador@veltrix.test', 'safe-password').subscribe();
    const csrf = http.expectOne('/api/v1/auth/csrf');
    csrf.flush({ token: 'csrf-token' });
    const request = http.expectOne('/api/v1/auth/login');
    expect(request.request.headers.get('X-CSRF-Token')).toBe('csrf-token');
    request.flush({ accessToken: token, tokenType: 'Bearer' });
    expect(service.authenticated()).toBe(true);
    expect(service.hasPermission('BILLING_READ')).toBe(true);
    expect(service.accessToken()).toBe(token);
  });

  it('marks the browser session on successful login', () => {
    service.login('operador@veltrix.test', 'safe-password').subscribe();
    http.expectOne('/api/v1/auth/csrf').flush({ token: 'csrf-token' });
    http.expectOne('/api/v1/auth/login').flush({ accessToken: jwt(), tokenType: 'Bearer' });
    expect(localStorage.getItem(SESSION_MARKER)).toBe('1');
  });

  it('skips refresh entirely on anonymous visits (no session marker)', async () => {
    await service.initialize();
    http.expectNone('/api/v1/auth/csrf');
    http.expectNone('/api/v1/auth/refresh');
    http.expectNone('/api/v1/me');
    expect(service.sessionLoading()).toBe(false);
    expect(service.authenticated()).toBe(false);
    await service.whenSessionReady(); // resolve mesmo sem refresh — guards não ficam pendurados
  });

  it('restores the session on initialize when the marker is present', async () => {
    localStorage.setItem(SESSION_MARKER, '1');
    const pending = service.initialize();
    http.expectOne('/api/v1/auth/csrf').flush({ token: 'csrf-token' });
    http.expectOne('/api/v1/auth/refresh').flush({ accessToken: jwt(), tokenType: 'Bearer' });
    http.expectOne('/api/v1/me').flush({ id: 7, email: 'operador@veltrix.test', name: 'Operador' });
    await pending;
    expect(service.authenticated()).toBe(true);
    expect(service.user()?.email).toBe('operador@veltrix.test');
    expect(service.sessionLoading()).toBe(false);
  });

  it('drops the stale marker when refresh answers 401', async () => {
    localStorage.setItem(SESSION_MARKER, '1');
    const pending = service.initialize();
    http.expectOne('/api/v1/auth/csrf').flush({ token: 'csrf-token' });
    http.expectOne('/api/v1/auth/refresh').flush({ message: 'expired' }, { status: 401, statusText: 'Unauthorized' });
    await pending;
    expect(localStorage.getItem(SESSION_MARKER)).toBeNull();
    expect(service.authenticated()).toBe(false);
    expect(service.sessionLoading()).toBe(false);
  });

  it('keeps the marker on transient failures (non-401) so the next visit retries', async () => {
    localStorage.setItem(SESSION_MARKER, '1');
    const pending = service.initialize();
    http.expectOne('/api/v1/auth/csrf').flush({ message: 'down' }, { status: 503, statusText: 'Service Unavailable' });
    await pending;
    expect(localStorage.getItem(SESSION_MARKER)).toBe('1');
    expect(service.authenticated()).toBe(false);
  });

  it('retries refresh once after a 403 (CSRF overwritten by another tab)', async () => {
    localStorage.setItem(SESSION_MARKER, '1');
    const pending = service.initialize();
    http.expectOne('/api/v1/auth/csrf').flush({ token: 'stale' });
    http.expectOne('/api/v1/auth/refresh').flush({ message: 'csrf' }, { status: 403, statusText: 'Forbidden' });
    http.expectOne('/api/v1/auth/csrf').flush({ token: 'fresh' });
    const retry = http.expectOne('/api/v1/auth/refresh');
    expect(retry.request.headers.get('X-CSRF-Token')).toBe('fresh');
    retry.flush({ accessToken: jwt(), tokenType: 'Bearer' });
    http.expectOne('/api/v1/me').flush({ id: 7, email: 'operador@veltrix.test', name: 'Operador' });
    await pending;
    expect(service.authenticated()).toBe(true);
    expect(localStorage.getItem(SESSION_MARKER)).toBe('1');
  });

  it('clears the marker on logout', () => {
    service.login('operador@veltrix.test', 'safe-password').subscribe();
    http.expectOne('/api/v1/auth/csrf').flush({ token: 'csrf-token' });
    http.expectOne('/api/v1/auth/login').flush({ accessToken: jwt(), tokenType: 'Bearer' });
    expect(localStorage.getItem(SESSION_MARKER)).toBe('1');
    service.logout();
    http.expectOne('/api/v1/auth/logout').flush(null);
    expect(localStorage.getItem(SESSION_MARKER)).toBeNull();
    expect(service.authenticated()).toBe(false);
  });
});
