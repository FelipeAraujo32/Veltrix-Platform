import { ApplicationConfig, inject, provideAppInitializer, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideRouter, withInMemoryScrolling } from '@angular/router';
import { provideHttpClient, withInterceptors } from '@angular/common/http';

import { routes } from './app.routes';
import { apiInterceptor } from '@veltrix/shared-client/http/api.interceptor';
import { AuthService } from '@veltrix/shared-client/services/auth.service';
import { SeoService } from './core/services/seo.service';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes, withInMemoryScrolling({ anchorScrolling: 'enabled' })),
    provideHttpClient(withInterceptors([apiInterceptor])),
    // Não-bloqueante: dispara a restauração da sessão sem travar o bootstrap.
    // O header exibe skeleton (auth.sessionLoading) e os guards aguardam auth.whenSessionReady().
    provideAppInitializer(() => { void inject(AuthService).initialize(); }),
    // Metadados por rota (description/canonical/og:*) — ver core/services/seo.service.ts.
    provideAppInitializer(() => { inject(SeoService).init(); }),
  ],
};
