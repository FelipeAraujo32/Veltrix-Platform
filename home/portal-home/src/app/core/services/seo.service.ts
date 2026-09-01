import { DOCUMENT, inject, Injectable } from '@angular/core';
import { Meta, Title } from '@angular/platform-browser';
import { NavigationEnd, Router } from '@angular/router';
import { filter } from 'rxjs';

/** Metadados por rota, declarados em `data.seo` (app.routes.ts). */
export interface RouteSeo {
  description?: string;
  /** Rotas autenticadas/utilitárias ficam fora do índice (robots noindex). */
  noindex?: boolean;
}

/** Mesma description do index.html — fallback para rotas sem `data.seo`. */
const DEFAULT_DESCRIPTION =
  'Sistemas de atendimento para órgãos públicos e empresas em uma plataforma modular: um login por pessoa, uma fatura por organização — contrate só o que precisa.';

/**
 * Aplica metadados por rota a cada NavigationEnd. canonical/og:url/og:image são montados em
 * runtime a partir de location.origin porque o domínio muda por ambiente (PORTAL_DOMAIN).
 */
@Injectable({ providedIn: 'root' })
export class SeoService {
  private readonly router = inject(Router);
  private readonly meta = inject(Meta);
  private readonly title = inject(Title);
  private readonly document = inject(DOCUMENT);
  private canonical: HTMLLinkElement | null = null;

  init(): void {
    const origin = this.document.location.origin;
    this.canonical = this.document.head.querySelector('link[rel="canonical"]');
    if (!this.canonical) {
      this.canonical = this.document.createElement('link');
      this.canonical.setAttribute('rel', 'canonical');
      this.document.head.appendChild(this.canonical);
    }
    this.meta.updateTag({ property: 'og:image', content: `${origin}/og-image.png` });
    this.meta.updateTag({ property: 'og:image:width', content: '1200' });
    this.meta.updateTag({ property: 'og:image:height', content: '630' });
    this.router.events
      .pipe(filter((event): event is NavigationEnd => event instanceof NavigationEnd))
      .subscribe(event => this.apply(origin, event.urlAfterRedirects));
  }

  /** O router já aplicou o Title da rota quando o NavigationEnd é emitido. */
  private apply(origin: string, url: string): void {
    const seo = this.routeSeo();
    const description = seo?.description ?? DEFAULT_DESCRIPTION;
    this.meta.updateTag({ name: 'description', content: description });
    this.meta.updateTag({ property: 'og:description', content: description });
    this.meta.updateTag({ property: 'og:title', content: this.title.getTitle() });
    const canonicalUrl = origin + (url.split('?')[0].split('#')[0] || '/');
    this.canonical?.setAttribute('href', canonicalUrl);
    this.meta.updateTag({ property: 'og:url', content: canonicalUrl });
    if (seo?.noindex) this.meta.updateTag({ name: 'robots', content: 'noindex, nofollow' });
    else this.meta.removeTag('name="robots"');
  }

  private routeSeo(): RouteSeo | undefined {
    let route = this.router.routerState.root;
    while (route.firstChild) route = route.firstChild;
    return route.snapshot.data['seo'] as RouteSeo | undefined;
  }
}
