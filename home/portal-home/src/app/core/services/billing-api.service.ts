import{HttpClient}from'@angular/common/http';import{inject,Injectable}from'@angular/core';import{Observable}from'rxjs';import{AppsResponse}from'../models/commercial.models';
// Só o /me/apps (Área do cliente). As operações de checkout/assinatura saíram do
// kernel junto com a UI de comércio — voltam na UI própria do módulo billing.
@Injectable({providedIn:'root'})export class BillingApiService{private readonly http=inject(HttpClient);apps():Observable<AppsResponse>{return this.http.get<AppsResponse>('/api/v1/me/apps')}}
