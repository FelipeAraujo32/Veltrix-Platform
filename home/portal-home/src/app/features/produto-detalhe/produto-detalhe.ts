import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService } from '@veltrix/shared-client/services/auth.service';
import { BillingCycle, PlanTier, Product, brl, findProductBySlug, tierPrice } from '../../core/pricing';

@Component({
  selector: 'app-produto-detalhe',
  imports: [RouterLink],
  templateUrl: './produto-detalhe.html',
  styleUrl: './produto-detalhe.scss',
})
export class ProdutoDetalhe {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  protected readonly auth = inject(AuthService);

  protected readonly brl = brl;
  protected readonly cycle = signal<BillingCycle>('MONTHLY');
  protected readonly product = signal<Product | null>(null);

  constructor() {
    const product = findProductBySlug(this.route.snapshot.paramMap.get('slug'));
    if (!product || product.status !== 'AVAILABLE') { void this.router.navigateByUrl('/produtos'); return; }
    this.product.set(product);
  }

  protected setCycle(cycle: BillingCycle): void { this.cycle.set(cycle); }
  protected price(tier: PlanTier): number { return tierPrice(tier, this.cycle()); }
  protected total(tier: PlanTier): number { return this.cycle() === 'YEARLY' ? tier.yearly * 12 : tier.monthly; }
}
