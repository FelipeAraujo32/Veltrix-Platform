// Catálogo da plataforma — cada produto tem SEUS PRÓPRIOS PLANOS (tiers), cada plano
// com preço e benefícios distintos. MOCK do front — o backend deve expor um endpoint
// público com esta forma. O preço final é reconfirmado pelo servidor na contratação.

export type BillingCycle = 'MONTHLY' | 'YEARLY';

export interface PlanTier {
  code: string;             // BASICO / PROFISSIONAL / AVANCADO
  name: string;
  tagline: string;
  /** preço/mês no ciclo mensal */
  monthly: number;
  /** preço/mês equivalente quando cobrado anualmente */
  yearly: number;
  highlight: boolean;
  features: string[];       // o que este plano dá
}

export interface Product {
  key: string;              // service_key do módulo (ex.: RELATORIOS)
  name: string;
  tagline: string;
  description: string;
  status: 'AVAILABLE' | 'SOON';
  currency: string;
  benefits: string[];       // por que assinar o produto (geral)
  tiers: PlanTier[];        // planos com preços/benefícios distintos
}

export const PRODUCTS: Product[] = [
  { key: 'RELATORIOS', name: 'Relatórios', status: 'SOON', currency: 'BRL', tagline: '', description: 'Painéis e indicadores consolidados dos módulos contratados, com exportação e visões por período.', benefits: [], tiers: [] },
  { key: 'ATENDIMENTO', name: 'Atendimento', status: 'SOON', currency: 'BRL', tagline: '', description: 'Central de chamados e solicitações internas com fluxos configuráveis e histórico por solicitante.', benefits: [], tiers: [] },
  { key: 'CADASTROS', name: 'Cadastros', status: 'SOON', currency: 'BRL', tagline: '', description: 'Base central de pessoas, organizações e contextos reaproveitada por todos os módulos da plataforma.', benefits: [], tiers: [] },
];

export function findProduct(key: string | null): Product | undefined {
  return PRODUCTS.find(product => product.key === key);
}

export function findProductBySlug(slug: string | null): Product | undefined {
  const normalized = (slug ?? '').toLowerCase();
  return PRODUCTS.find(product => product.key.toLowerCase() === normalized);
}

export function findTier(product: Product, code: string | null): PlanTier | undefined {
  return product.tiers.find(tier => tier.code === code);
}

export function tierPrice(tier: PlanTier, cycle: BillingCycle): number {
  return cycle === 'YEARLY' ? tier.yearly : tier.monthly;
}

/** Menor preço entre os planos do produto (para o "a partir de" no card). */
export function productFromPrice(product: Product, cycle: BillingCycle): number {
  if (!product.tiers.length) return 0;
  return Math.min(...product.tiers.map(tier => tierPrice(tier, cycle)));
}

export function brl(value: number): string {
  return `R$ ${value.toLocaleString('pt-BR')}`;
}
