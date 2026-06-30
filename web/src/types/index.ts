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

export interface GroupMembershipChange {
  groupName: string;
  action: 'add' | 'remove';
}

export interface UserGroupStatus {
  group: Group;
  isMember: boolean;
  membershipType: 'direct' | 'nested';
}
