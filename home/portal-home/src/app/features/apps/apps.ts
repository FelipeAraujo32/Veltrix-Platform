import { Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { BillingApiService } from '../../core/services/billing-api.service';
import { ApplicationAccess } from '../../core/models/commercial.models';
import { RuntimeConfigService } from '@veltrix/shared-client/services/runtime-config.service';

@Component({ selector: 'app-apps', imports: [RouterLink], templateUrl: './apps.html', styleUrl: './apps.scss' })
export class Apps {
  private readonly api = inject(BillingApiService);
  private readonly runtime = inject(RuntimeConfigService);
  protected readonly loading = signal(true);
  protected readonly error = signal('');
  protected readonly applications = signal<ApplicationAccess[]>([]);

  constructor() {
    this.api.apps().subscribe({
      next: r => {
        this.applications.set(r.applications.filter(a => ['AVAILABLE', 'TRIAL', 'GRACE_PERIOD'].includes(a.accessStatus)));
        this.loading.set(false);
      },
      error: e => {
        // Sem o módulo billing no kernel, /me/apps não existe (404 do gateway):
        // mostra o estado vazio ("nenhum sistema"), não um erro.
        if (e.status === 404) { this.applications.set([]); this.loading.set(false); return; }
        this.error.set(e.friendlyMessage ?? 'Não foi possível carregar os sistemas.');
        this.loading.set(false);
      },
    });
  }

  /** Resolve a URL do módulo SEM conhecer módulos: lookup em runtime.moduleBaseUrls (config). */
  protected appUrl(app: ApplicationAccess): string {
    if (/^https?:\/\//.test(app.url)) return app.url;
    const base = this.runtime.moduleBaseUrls[app.productKey?.toUpperCase() ?? ''];
    if (!base) return app.url;
    return base + app.url.replace(new RegExp(`^/${(app.productKey ?? '').toLowerCase()}`), '');
  }
}
