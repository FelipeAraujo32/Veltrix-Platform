import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class CorrelationService {
  create(): string {
    return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
}
