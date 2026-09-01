import { HttpClient, HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { computed, inject, Injectable, signal } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, firstValueFrom, Observable, switchMap, tap, throwError } from 'rxjs';
import { CurrentUser, JwtClaims, TokenResponse } from '../models/api.models';

/** Sessão compartilhada entre abas para evitar refreshes redundantes (ver initialize). */
interface SharedSession {
  accessToken: string;
  user: CurrentUser | null;
  at: number;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly router = inject(Router);
  private readonly accessTokenState = signal<string | null>(null);
  private readonly csrfTokenState = signal<string | null>(null);
  private readonly claimsState = signal<JwtClaims | null>(null);
  private readonly userState = signal<CurrentUser | null>(null);
  /** true enquanto a sessão inicial (csrf→refresh→me) ainda não resolveu. */
  private readonly sessionLoadingState = signal(true);

  // --- coordenação de refresh entre abas (single-flight) ---
  /** Nome do Web Lock que serializa o csrf→refresh→me entre abas do mesmo navegador. */
  private static readonly REFRESH_LOCK = 'veltrix-auth-refresh';
  /**
   * Marcador em localStorage de que houve login neste navegador. Sem ele, initialize() nem tenta
   * o refresh — visitante anônimo não deve gerar POST /auth/refresh com 401 a cada visita.
   */
  private static readonly SESSION_MARKER = 'veltrix.session';
  /** Canal usado para compartilhar o resultado do refresh com as demais abas. */
  private static readonly SESSION_CHANNEL = 'veltrix-auth-session';
  /** Janela na qual o resultado de um refresh recente pode ser reaproveitado por outra aba. */
  private static readonly SHARE_TTL_MS = 15_000;
  private readonly channel = this.openChannel();
  private sharedSession: SharedSession | null = null;

  /** Resolve quando a sessão inicial termina (com sucesso ou falha); guards a aguardam. */
  private resolveSessionReady!: () => void;
  private readonly sessionReady = new Promise<void>(resolve => (this.resolveSessionReady = resolve));

  constructor() {
    this.channel?.addEventListener('message', event => this.onSharedSession((event as MessageEvent).data as SharedSession | null));
  }

  /** Promessa que os guards aguardam para não decidir a rota antes de a sessão resolver. */
  whenSessionReady(): Promise<void> { return this.sessionReady; }

  readonly accessToken = this.accessTokenState.asReadonly();
  readonly csrfToken = this.csrfTokenState.asReadonly();
  readonly claims = this.claimsState.asReadonly();
  readonly user = this.userState.asReadonly();
  readonly authenticated = computed(() => {
    const claims = this.claimsState();
    return !!claims && (!claims.exp || claims.exp * 1000 > Date.now());
  });
  /** Alias semântico de `authenticated` para uso em templates/CTAs. */
  readonly isAuthenticated = this.authenticated;
  /** Fonte única do destino "Área do cliente": /apps se autenticado, senão /login. */
  readonly areaClienteLink = computed(() => (this.authenticated() ? '/apps' : '/login'));
  /** true enquanto a sessão inicial não resolveu — usado para exibir skeleton no header. */
  readonly sessionLoading = this.sessionLoadingState.asReadonly();
  readonly permissions = computed(() => new Set(this.claimsState()?.permissions ?? []));

  login(email: string, password: string): Observable<TokenResponse> {
    return this.ensureCsrf().pipe(switchMap(() => this.http.post<TokenResponse>('/api/v1/auth/login', { email, password }, this.csrfOptions())), tap(tokens => this.acceptTokens(tokens)));
  }

  /**
   * Restaura a sessão a partir do cookie de refresh. Coordena as abas com um Web Lock para que
   * apenas uma execute o csrf→refresh→me: as demais reaproveitam o resultado compartilhado, o que
   * evita (a) o cookie de CSRF ser sobrescrito entre abas e (b) a corrida de rotação do refresh
   * token. Cf. docs/auth-refresh-multitab.md para a recomendação de grace period no backend.
   */
  async initialize(): Promise<void> {
    if (!this.hasSessionMarker()) {
      // Nunca houve login neste navegador (ou houve logout): não há cookie de refresh a restaurar.
      this.sessionLoadingState.set(false);
      this.resolveSessionReady();
      return;
    }
    try {
      await this.withRefreshLock(async () => {
        if (this.adoptSharedSession()) return; // outra aba acabou de renovar: reaproveita
        await firstValueFrom(this.ensureCsrf().pipe(switchMap(() => this.restoreWithRetry()), switchMap(() => this.loadCurrentUser())));
      });
    } catch (failure) {
      // 401 = cookie de refresh inválido/expirado: o marcador está obsoleto. Outras falhas
      // (rede, 5xx, 403 residual) mantêm o marcador para tentar de novo na próxima visita.
      if ((failure as HttpErrorResponse)?.status === 401) this.clearSessionMarker();
      this.clear();
    } finally {
      this.sessionLoadingState.set(false);
      this.resolveSessionReady();
    }
  }

  restore(): Observable<TokenResponse> {
    return this.http.post<TokenResponse>('/api/v1/auth/refresh', {}, this.csrfOptions()).pipe(tap(tokens => this.acceptTokens(tokens)));
  }

  loadCurrentUser(): Observable<CurrentUser> {
    return this.http.get<CurrentUser>('/api/v1/me').pipe(tap(user => { this.userState.set(user); this.publishSession(); }));
  }

  logout(redirectUrl = '/'): void {
    this.http.post<void>('/api/v1/auth/logout', {}, this.csrfOptions()).subscribe({ error: () => undefined });
    this.clearSessionMarker();
    this.clear();
    void this.router.navigateByUrl(redirectUrl);
  }

  hasPermission(permission: string): boolean { return this.permissions().has(permission); }

  /** Renova e tenta o refresh mais uma vez em caso de 403 (CSRF sobrescrito por outra aba). */
  private restoreWithRetry(): Observable<TokenResponse> {
    return this.restore().pipe(
      catchError((failure: HttpErrorResponse) => {
        if (failure?.status !== 403) return throwError(() => failure);
        return this.ensureCsrf().pipe(switchMap(() => this.restore()));
      }),
    );
  }

  /** Serializa o refresh entre abas com navigator.locks; sem suporte, executa direto (best-effort). */
  private async withRefreshLock(run: () => Promise<void>): Promise<void> {
    const locks = typeof navigator !== 'undefined' ? navigator.locks : undefined;
    if (!locks?.request) { await run(); return; }
    await locks.request(AuthService.REFRESH_LOCK, run);
  }

  private openChannel(): BroadcastChannel | null {
    if (typeof BroadcastChannel === 'undefined') return null;
    try { return new BroadcastChannel(AuthService.SESSION_CHANNEL); } catch { return null; }
  }

  /** Aplica uma sessão recebida de outra aba quando esta ainda não está autenticada. */
  private onSharedSession(data: SharedSession | null): void {
    if (!data?.accessToken) return;
    this.sharedSession = data;
    if (!this.authenticated()) { this.acceptTokens({ accessToken: data.accessToken, tokenType: 'Bearer' }); if (data.user) this.userState.set(data.user); }
  }

  /** Reaproveita o resultado de um refresh recente de outra aba, dentro da janela de validade. */
  private adoptSharedSession(): boolean {
    const shared = this.sharedSession;
    if (!shared || Date.now() - shared.at > AuthService.SHARE_TTL_MS) return false;
    this.acceptTokens({ accessToken: shared.accessToken, tokenType: 'Bearer' });
    if (shared.user) this.userState.set(shared.user);
    return this.authenticated();
  }

  /** Compartilha a sessão atual (token de acesso + usuário) com as demais abas do mesmo navegador. */
  private publishSession(): void {
    const accessToken = this.accessTokenState();
    if (!accessToken) return;
    const shared: SharedSession = { accessToken, user: this.userState(), at: Date.now() };
    this.sharedSession = shared;
    this.channel?.postMessage(shared);
  }

  private ensureCsrf(): Observable<{ token: string }> {
    return this.http.get<{ token: string }>('/api/v1/auth/csrf').pipe(tap(value => this.csrfTokenState.set(value.token)));
  }
  private csrfOptions(): { headers: HttpHeaders } {
    const token = this.csrfTokenState();
    return { headers: token ? new HttpHeaders({ 'X-CSRF-Token': token }) : new HttpHeaders() };
  }
  private acceptTokens(tokens: TokenResponse): void { this.accessTokenState.set(tokens.accessToken); this.claimsState.set(this.decode(tokens.accessToken)); this.setSessionMarker(); }

  // localStorage pode estar indisponível (modo privado, SSR): degrada para "sem sessão",
  // que só custa um login manual após recarregar — nunca um refresh anônimo.
  private hasSessionMarker(): boolean {
    try { return localStorage.getItem(AuthService.SESSION_MARKER) === '1'; } catch { return false; }
  }
  private setSessionMarker(): void {
    try { localStorage.setItem(AuthService.SESSION_MARKER, '1'); } catch { /* sem storage */ }
  }
  private clearSessionMarker(): void {
    try { localStorage.removeItem(AuthService.SESSION_MARKER); } catch { /* sem storage */ }
  }
  private clear(): void { this.accessTokenState.set(null); this.claimsState.set(null); this.userState.set(null); }
  private decode(token: string): JwtClaims | null {
    try {
      const encoded = token.split('.')[1]; if (!encoded) return null;
      const normalized = encoded.replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(decodeURIComponent(Array.from(atob(normalized), char => `%${char.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''))) as JwtClaims;
    } catch { return null; }
  }
}
