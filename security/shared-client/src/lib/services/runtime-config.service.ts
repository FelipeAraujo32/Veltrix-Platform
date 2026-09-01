import { Injectable } from '@angular/core';

/**
 * Marca do cliente aplicada em runtime (sem rebuild). Preenchida por
 * window.__VELTRIX_CONFIG__.branding, que em produção vem do runtime-config.js
 * gerado pelo nginx via envsubst de variáveis de ambiente (BRAND_*). Campos
 * vazios caem no default Veltrix — cada cliente sobrescreve só o que quiser.
 */
export interface VeltrixBranding {
  clientName: string;    // nome do cliente exibido (ex.: "MedMais")
  productLabel: string;  // rótulo do produto sob o nome (ex.: "Atendimento")
  logoUrl?: string;      // logo em imagem (same-origin ou data: — CSP img-src 'self' data:)
  logoText: string;      // marca textual quando não há logoUrl (ex.: "M")
  primaryColor?: string; // cor de marca (hex) — reskin em runtime
  accentColor?: string;  // cor de destaque/sinal (hex)
  heroKicker: string;    // eyebrow do hero
  heroTitle: string;     // título do hero
  heroSubtitle: string;  // subtítulo do hero
  footerNote: string;    // aviso de privacidade no rodapé
}

interface VeltrixRuntimeConfig {
  apiBaseUrl?: string;
  portalUrl?: string;
  branding?: Partial<VeltrixBranding>;
  /** productKey (maiúsculo) -> origem pública do micro-frontend do módulo. Novo módulo = nova entrada, zero código. */
  moduleBaseUrls?: Record<string, string>;
}

declare global {
  interface Window { __VELTRIX_CONFIG__?: VeltrixRuntimeConfig; }
}

const DEFAULT_BRANDING: VeltrixBranding = {
  clientName: 'Veltrix',
  productLabel: '',
  logoText: 'V',
  heroKicker: 'Atendimento oficial',
  heroTitle: 'Seus sistemas em um só acesso.',
  heroSubtitle: 'Acesse os módulos contratados pela sua organização com um único login.',
  footerNote: 'Seus dados são tratados conforme a política de privacidade do contexto responsável.',
};

@Injectable({ providedIn: 'root' })
export class RuntimeConfigService {
  readonly apiBaseUrl = this.normalize(window.__VELTRIX_CONFIG__?.apiBaseUrl ?? '');
  readonly portalUrl = this.normalize(window.__VELTRIX_CONFIG__?.portalUrl ?? 'http://localhost:4200');
  readonly branding: VeltrixBranding = this.resolveBranding();
  /** Mapa productKey -> origem do micro-frontend do módulo (só config: plugar módulo = nova entrada, zero código). */
  readonly moduleBaseUrls: Record<string, string> = this.resolveModuleBaseUrls();

  api(path: string): string { return `${this.apiBaseUrl}${path}`; }

  private resolveModuleBaseUrls(): Record<string, string> {
    const map: Record<string, string> = {};
    const raw = window.__VELTRIX_CONFIG__?.moduleBaseUrls ?? {};
    for (const [key, value] of Object.entries(raw)) {
      if (typeof value === 'string' && value.trim() !== '') map[key.toUpperCase()] = this.normalize(value);
    }
    return map;
  }

  private normalize(value: string): string { return value.replace(/\/$/, ''); }

  /** Mescla a marca do cliente sobre o default, ignorando strings vazias (envsubst não preenchido). */
  private resolveBranding(): VeltrixBranding {
    const raw = window.__VELTRIX_CONFIG__?.branding ?? {};
    const clean: Partial<VeltrixBranding> = {};
    (Object.keys(raw) as (keyof VeltrixBranding)[]).forEach(key => {
      const value = raw[key];
      if (typeof value === 'string' ? value.trim() !== '' : value != null) (clean as Record<string, unknown>)[key] = value;
    });
    return { ...DEFAULT_BRANDING, ...clean };
  }
}
