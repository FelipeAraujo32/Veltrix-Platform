import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';
import { CorrelationService } from '../services/correlation.service';
import { RuntimeConfigService } from '../services/runtime-config.service';
import { ApiError } from '../models/api.models';

export const apiInterceptor: HttpInterceptorFn = (request, next) => {
  const auth = inject(AuthService);
  const runtime = inject(RuntimeConfigService);
  const correlation = inject(CorrelationService);
  const token = auth.accessToken();
  const headers: Record<string, string> = { 'X-Correlation-Id': correlation.create() };
  if (token && !request.url.endsWith('/auth/refresh')) headers['Authorization'] = `Bearer ${token}`;
  const url = request.url.startsWith('/api/') ? runtime.api(request.url) : request.url;

  return next(request.clone({ url, setHeaders: headers, withCredentials: true })).pipe(
    catchError((failure: HttpErrorResponse) => {
      const apiError = failure.error as Partial<ApiError> | null;
      const message = apiError?.message || (failure.status === 0 ? 'Não foi possível conectar ao serviço.' : 'Não foi possível concluir a operação.');
      return throwError(() => ({ ...failure, friendlyMessage: message, correlationId: apiError?.correlationId }));
    }),
  );
};
