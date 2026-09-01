import { Component, inject } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { findProduct, findTier } from '../../core/pricing';

// TODO: trocar pelo e-mail comercial definitivo quando o domínio estiver no ar.
const EMAIL_COMERCIAL = 'comercial@veltrix.com.br';

@Component({ selector: 'app-contato', imports: [RouterLink], templateUrl: './contato.html', styleUrl: './contato.scss' })
export class Contato {
  private readonly route = inject(ActivatedRoute);

  readonly email = EMAIL_COMERCIAL;

  /** Interesse vindo dos CTAs de produto (produtos/:slug → /contato?produto=&plano=). */
  readonly interesse = (() => {
    const q = this.route.snapshot.queryParamMap;
    const produto = findProduct(q.get('produto'));
    if (!produto) return null;
    const tier = findTier(produto, q.get('plano'));
    return tier ? `${produto.name} — plano ${tier.name}` : produto.name;
  })();

  readonly mailto = (() => {
    const assunto = this.interesse ? `Interesse: ${this.interesse}` : 'Quero conhecer a Veltrix';
    const corpo = 'Olá! Gostaria de falar sobre a plataforma Veltrix.\n\n'
      + (this.interesse ? `Tenho interesse em: ${this.interesse}\n\n` : '')
      + 'Organização:\nComo é o atendimento hoje:\nTamanho da equipe:';
    return `mailto:${EMAIL_COMERCIAL}?subject=${encodeURIComponent(assunto)}&body=${encodeURIComponent(corpo)}`;
  })();
}
