import { Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService } from '@veltrix/shared-client/services/auth.service';
import { PRODUCTS } from '../../core/pricing';
import { ProdutoCard } from '../produtos/produto-card/produto-card';

@Component({
  selector: 'app-inicio',
  imports: [RouterLink, ProdutoCard],
  templateUrl: './inicio.html',
  styleUrl: './inicio.scss',
})
export class Inicio {
  protected readonly auth = inject(AuthService);
  /** Catálogo da seção "Módulos" — mesma fonte de /produtos. */
  protected readonly products = PRODUCTS;
  /** Metade da esteira do hero (4 cópias do catálogo); o template desenha 2 metades
   *  idênticas por fileira — o loop da animação salta -50% sem emenda visível. */
  protected readonly marquee = Array(4).fill(PRODUCTS).flat();
}
