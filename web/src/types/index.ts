export interface User {
  dn: string;
  sAMAccountName: string;
  userPrincipalName?: string;
  displayName?: string;
  givenName?: string;
  sn?: string;
  mail?: string;
  department?: string;
  title?: string;
  manager?: string;
  memberOf?: string[];
  description?: string;
  telephoneNumber?: string;
  mobile?: string;
  employeeID?: string;
  company?: string;
  streetAddress?: string;
  l?: string;
  st?: string;
  postalCode?: string;
  c?: string;
  whenCreated?: string;
  whenChanged?: string;
  enabled: boolean;
  attributes?: Record<string, string>;
  accountExpires?: string | null;
  pwdLastSet?: string | null;
  passwordExpiryDate?: string | null;
}

export interface Group {
  dn: string;
  cn: string;
  sAMAccountName: string;
  description?: string;
  groupType?: string;
  members?: string[];
  memberOf?: string[];
  distinguishedName?: string;
  /** Membership comes via another group rather than directly from the user object. */
  nested?: boolean;
}

export interface GroupMember {
  dn: string;
  cn: string;
  sAMAccountName?: string;
  displayName?: string;
  mail?: string;
  /** Member is itself a group, so it links to that group's page rather than a user page. */
  isGroup?: boolean;
}

export interface GroupDetailResponse {
  success: boolean;
  message?: string;
  group?: Group;
  members?: GroupMember[];
  memberCount: number;
  /** The directory capped the member list, so more members exist than are shown. */
  truncated?: boolean;
  error?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  success: boolean;
  sessionId?: string;
  message?: string;
  user?: User;
}

export interface APIResponse<T = unknown> {
  success: boolean;
  message?: string;
  data?: T;
  error?: string;
}

export interface UserResponse {
  success: boolean;
  message?: string;
  user?: User;
  error?: string;
}

export interface GroupsResponse {
  success: boolean;
  message?: string;
  groups?: Group[];
  count: number;
  error?: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  environment: string;
  timestamp: string;
  adServer?: string;
  adPort?: number;
}

export interface SearchEntry {
  dn: string;
  attributes: Record<string, string[]>;
}

export interface SearchResponse {
  success: boolean;
  message?: string;
  entries?: SearchEntry[];
  count: number;
  error?: string;
}

export interface SessionInfo {
  sessionId: string;
  username: string;
  userDN: string;
  createdAt: string;
  expiresAt: string;
  canSearch: boolean;
}

export interface GroupMembershipChange {
  groupName: string;
  action: 'add' | 'remove';
}

export interface UserGroupStatus {
  group: Group;
  isMember: boolean;
  membershipType: 'direct' | 'nested';
}
