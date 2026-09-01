export interface ApiError {
  error: string;
  message: string;
  correlationId?: string;
  timestamp?: string;
}

export interface TokenResponse {
  accessToken: string;
  tokenType: string;
}

export interface CurrentUser {
  id: number;
  email: string;
  name: string;
}

export interface JwtClaims {
  sub: string;
  email?: string;
  name?: string;
  permissions?: string[];
  roles?: string[];
  contexts?: string[];
  tenant_id?: string;
  base_id?: string;
  access_version?: number;
  token_version?: number;
  exp?: number;
}

export interface ConfigurationItem {
  id: string;
  code: string;
  name: string;
}

export interface AudienceItem extends ConfigurationItem {
  description?: string;
  requiresAuthentication: boolean;
  allowsAnonymous: boolean;
}

export interface ChannelItem extends ConfigurationItem {
  channelType: string;
  requiresAuthentication: boolean;
}

export interface ManifestationCreateRequest {
  contextCode?: string;
  typeCode: string;
  categoryCode?: string;
  audienceCode?: string;
  subject: string;
  description: string;
  name?: string;
  document?: string;
  email?: string;
  phone?: string;
  originChannel: string;
  priority?: string;
  anonymous: boolean;
  address?: string;
  neighborhood?: string;
  region?: string;
  referencePoint?: string;
  latitude?: number;
  longitude?: number;
  locationConsent: boolean;
  qrCodeKey?: string;
  qrDataConfirmed: boolean;
  privacyAccepted: boolean;
  notificationChannels: string[];
  notificationConsent: boolean;
  formCode?: string;
  formDataJson?: string;
}

export interface ManifestationCreated {
  protocol: string;
  accessCode: string;
  status: string;
  createdAt: string;
  dueAt?: string;
  originChannel: string;
}

export interface ManifestationSummary {
  id: string;
  protocol: string;
  subject: string;
  description: string;
  status: string;
  createdAt: string;
  dueAt?: string;
  originChannel: string;
}

export interface PageResponse<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  number: number;
  size: number;
}

export interface Dashboard {
  contextCode: string;
  total: number;
  byStatus: Record<string, number>;
  byChannel: Record<string, number>;
  byType: Record<string, number>;
  byCategory: Record<string, number>;
  byNeighborhood: Record<string, number>;
  byUnit: Record<string, number>;
  overdue: number;
  averageSatisfaction?: number;
}

export interface WorkflowTransitionOption {
  status: string;
  name: string;
  requiresJustification: boolean;
}

export interface QrConfiguration {
  key: string;
  signature: string;
  contextCode: string;
  unitCode?: string;
  publicAssetCode?: string;
  categoryCode?: string;
  formCode?: string;
  channelCode?: string;
  configurationJson?: string;
  expiresAt?: string;
}
