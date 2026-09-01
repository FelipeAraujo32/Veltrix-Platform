import { Routes } from '@angular/router';
import { authGuard, guestGuard } from './core/guards/auth.guard';

/** Rotas autenticadas/utilitárias não entram no índice de busca. */
const NOINDEX = { seo: { noindex: true } };

export const routes: Routes = [
 {path:'',loadComponent:()=>import('./features/inicio/inicio').then(m=>m.Inicio),title:'Veltrix — Seus sistemas de atendimento em um só acesso'},
 {path:'produtos',loadComponent:()=>import('./features/produtos/produtos').then(m=>m.Produtos),title:'Produtos — Veltrix',data:{seo:{description:'Relatórios, Atendimento e Cadastros em breve — cada módulo no mesmo login e na mesma fatura, contrate só o que precisa.'}}},
 {path:'produtos/:slug',loadComponent:()=>import('./features/produto-detalhe/produto-detalhe').then(m=>m.ProdutoDetalhe),title:'Produto — Veltrix'},
 {path:'sobre',loadComponent:()=>import('./features/sobre/sobre').then(m=>m.Sobre),title:'Sobre — Veltrix',data:{seo:{description:'A Veltrix reúne sistemas de atendimento com um login por pessoa e uma fatura por organização.'}}},
 {path:'contato',loadComponent:()=>import('./features/contato/contato').then(m=>m.Contato),title:'Fale com a Veltrix',data:{seo:{description:'Fale com a Veltrix: conte como é a sua operação de atendimento e montamos o conjunto de módulos ideal para a sua organização.'}}},
 {path:'login',canActivate:[guestGuard],loadComponent:()=>import('./features/auth/login/login').then(m=>m.Login),title:'Área do cliente — Veltrix',data:NOINDEX},
 {path:'home',redirectTo:'',pathMatch:'full'},
 {path:'apps',canActivate:[authGuard],loadComponent:()=>import('./features/apps/apps').then(m=>m.Apps),title:'Área do cliente — Veltrix',data:NOINDEX},
 {path:'access-denied',loadComponent:()=>import('./features/access-denied/access-denied').then(m=>m.AccessDenied),title:'Acesso negado',data:NOINDEX},
 {path:'**',loadComponent:()=>import('./features/not-found/not-found').then(m=>m.NotFound),title:'Página não encontrada',data:NOINDEX}
];
