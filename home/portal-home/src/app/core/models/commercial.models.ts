// Contratos do /me/apps (Área do cliente). Os tipos de catálogo/assinatura/checkout
// saíram do kernel junto com a UI de comércio — voltam na UI própria do módulo billing.
export type AccessStatus='AVAILABLE'|'TRIAL'|'GRACE_PERIOD'|'NOT_CONTRACTED'|'SUSPENDED'|'NO_PERMISSION'|'TEMPORARILY_UNAVAILABLE';
export interface ApplicationAccess{productKey:string;name:string;description?:string;url:string;icon?:string;accessStatus:AccessStatus;features:string[];limits:Record<string,unknown>}
export interface AppsResponse{userId:string;tenantId:string;baseId?:string;applications:ApplicationAccess[]}
