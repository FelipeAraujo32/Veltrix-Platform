import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '@veltrix/shared-client/services/auth.service';

export const authGuard: CanActivateFn = async (_route, state) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  // Com a sessão restaurada de forma não-bloqueante, aguarda o resultado antes de decidir
  // para não redirecionar um usuário já autenticado ao acessar /apps diretamente.
  await auth.whenSessionReady();
  return auth.authenticated() || router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });
};

/** Impede que um usuário já autenticado abra /login: manda para o returnUrl interno ou /apps. */
export const guestGuard: CanActivateFn = async route => {
  const auth = inject(AuthService);
  const router = inject(Router);
  await auth.whenSessionReady();
  if (!auth.authenticated()) return true;
  const returnUrl = route.queryParamMap.get('returnUrl');
  const isInternal = !!returnUrl && returnUrl.startsWith('/') && !returnUrl.startsWith('//') && !returnUrl.includes('\\');
  return router.parseUrl(isInternal ? returnUrl : '/apps');
};
