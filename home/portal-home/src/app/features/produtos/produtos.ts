import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { PRODUCTS } from '../../core/pricing';
import { ProdutoCard } from './produto-card/produto-card';

@Component({
  selector: 'app-produtos',
  imports: [RouterLink, ProdutoCard],
  templateUrl: './produtos.html',
  styleUrl: './produtos.scss',
})
export class Produtos {
  protected readonly products = PRODUCTS;
}
