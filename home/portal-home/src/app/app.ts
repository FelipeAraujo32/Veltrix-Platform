import { Component, computed, ElementRef, HostListener, inject, signal, viewChild } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { filter } from 'rxjs';
import { AuthService } from '@veltrix/shared-client/services/auth.service';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  protected readonly menuOpen = signal(false);
  /** Menu hambúrguer da navegação principal (≤760px). */
  protected readonly navOpen = signal(false);
  private readonly navToggle = viewChild<ElementRef<HTMLButtonElement>>('navToggle');
  protected readonly year = new Date().getFullYear();

  /** Iniciais para o avatar: "Felipe Silva" → "FS"; e-mail sem nome → primeira letra. */
  protected readonly initials = computed(() => {
    const user = this.auth.user();
    const source = (user?.name || user?.email || '').trim();
    if (!source) return '·';
    const parts = source.split(/\s+/);
    const first = parts[0]?.[0] ?? '';
    const last = parts.length > 1 ? (parts[parts.length - 1][0] ?? '') : '';
    return (first + last).toUpperCase() || source[0].toUpperCase();
  });

  constructor() {
    // Fecha os menus ao navegar.
    this.router.events.pipe(filter(event => event instanceof NavigationEnd), takeUntilDestroyed()).subscribe(() => { this.menuOpen.set(false); this.navOpen.set(false); });
  }

  protected toggleMenu(): void { this.menuOpen.update(open => !open); }
  protected closeMenu(): void { this.menuOpen.set(false); }
  protected toggleNav(): void { this.navOpen.update(open => !open); }

  @HostListener('document:keydown.escape')
  protected onEscape(): void {
    if (this.navOpen()) { this.navOpen.set(false); this.navToggle()?.nativeElement.focus(); } // devolve o foco ao botão
    this.menuOpen.set(false);
  }

  @HostListener('document:click', ['$event'])
  protected onDocumentClick(event: MouseEvent): void {
    if (!this.menuOpen()) return;
    const target = event.target as HTMLElement | null;
    if (!target?.closest('.user-menu')) this.menuOpen.set(false);
  }
}
