import { Component, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Product, brl, productFromPrice } from '../../../core/pricing';

/** Card de produto do catálogo — usado em /produtos e na seção "Módulos" da home. */
@Component({
  selector: 'app-produto-card',
  imports: [RouterLink],
  templateUrl: './produto-card.html',
  styleUrl: './produto-card.scss',
})
export class ProdutoCard {
  readonly product = input.required<Product>();
  protected readonly brl = brl;
  /** "a partir de" = menor preço entre os planos no ciclo anual. */
  protected fromPrice(product: Product): number { return productFromPrice(product, 'YEARLY'); }
}
