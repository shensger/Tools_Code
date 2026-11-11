// ─── Auth ─────────────────────────────────────────────────────────────────────

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

// ─── Pagination ───────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  results: T[];
  has_more: boolean;
  last_cursor?: number | string;
}

export interface CursorPage<T> {
  results?: T[];
  cursor?: string;
}

// ─── Organizations ────────────────────────────────────────────────────────────

export interface Organization {
  id: number;
  name: string;
  description?: string;
  nodeApprovalMode?: string;
  tags?: string[];
  fields?: Record<string, unknown>;
}

export interface OrganizationLocation {
  id: number;
  organizationId: number;
  name: string;
  address?: string;
  city?: string;
  state?: string;
  zip?: string;
  country?: string;
  phone?: string;
  description?: string;
}

// ─── Devices ─────────────────────────────────────────────────────────────────

export interface Device {
  id: number;
  parentDeviceId?: number;
  organizationId: number;
  locationId?: number;
  nodeClass: string;
  nodeRoleId?: number;
  rolePolicyId?: number;
  policyId?: number;
  approvalStatus?: string;
  offline?: boolean;
  displayName?: string;
  systemName?: string;
  dnsName?: string;
  netbiosName?: string;
  created?: string;
  lastContact?: string;
  lastUpdate?: string;
  ipAddresses?: string[];
  macAddresses?: string[];
  publicIp?: string;
  os?: {
    name?: string;
    manufacturer?: string;
    architecture?: string;
    buildNumber?: string;
    releaseId?: string;
    needsReboot?: boolean;
  };
  system?: {
    name?: string;
    manufacturer?: string;
    model?: string;
    serialNumber?: string;
    biosSerialNumber?: string;
  };
  tags?: string[];
  fields?: Record<string, unknown>;
}

export interface DeviceActivity {
  id: number;
  deviceId?: number;
  type?: string;
  status?: string;
  uid?: string;
  message?: string;
  userId?: number;
  userName?: string;
  created?: number;
  data?: Record<string, unknown>;
}

export interface WindowsService {
  name: string;
  displayName?: string;
  description?: string;
  state?: string;
  startType?: string;
  pid?: number;
  logOnAs?: string;
}

export interface DiskDrive {
  index?: number;
  name?: string;
  model?: string;
  manufacturer?: string;
  serialNumber?: string;
  capacity?: number;
  interfaceType?: string;
}

export interface Volume {
  name?: string;
  label?: string;
  deviceName?: string;
  fileSystem?: string;
  capacity?: number;
  freeSpace?: number;
}

export interface Processor {
  name?: string;
  manufacturer?: string;
  numCores?: number;
  numLogicalProcessors?: number;
  virtualizationFirmwareEnabled?: boolean;
}

export interface LastLoggedOnUser {
  userName?: string;
}

export interface DevicePolicyOverride {
  overrideType?: string;
  conditionId?: number;
  fieldName?: string;
  monitoringOverride?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface DeviceMaintenance {
  status?: string;
  start?: number;
  end?: number;
}

export interface DeviceGroup {
  id: number;
  name?: string;
  match?: string;
  query?: Record<string, unknown>;
}

// ─── Alerts ───────────────────────────────────────────────────────────────────

export interface Alert {
  uid: string;
  deviceId?: number;
  organizationId?: number;
  message?: string;
  subject?: string;
  type?: string;
  priority?: string;
  series?: string;
  severity?: string;
  created?: number;
  triggeredAt?: number;
  sourceConfigUid?: string;
  data?: Record<string, unknown>;
}

// ─── Scripting / Jobs ─────────────────────────────────────────────────────────

export interface ScriptingOption {
  id?: number;
  uid?: string;
  type?: "ACTION" | "SCRIPT" | string;
  name?: string;
  description?: string;
  language?: string;
  categories?: string[];
  scriptVariables?: ScriptVariable[];
  operatingSystem?: string;
}

export interface ScriptVariable {
  name: string;
  defaultValue?: string;
  required?: boolean;
  valueType?: string;
}

export interface JobEntry {
  uid?: string;
  id?: number;
  deviceId?: number;
  jobType?: string;
  type?: string;
  status?: string;
  createTime?: number;
  startTime?: number;
  endTime?: number;
  message?: string;
  [key: string]: unknown;
}

// ─── Patch & Software Management ──────────────────────────────────────────────

export interface SoftwareEntry {
  deviceId: number;
  name?: string;
  publisher?: string;
  version?: string;
  installDate?: string;
  location?: string;
}

export interface OsPatchEntry {
  deviceId: number;
  name?: string;
  kbNumber?: string;
  severity?: string;
  status?: string;
  installedAt?: string;
  type?: string;
}

export interface OsPatchInstallEntry {
  deviceId: number;
  name?: string;
  kbNumber?: string;
  status?: string;
  installedAt?: string;
  type?: string;
}

export interface SoftwarePatchEntry {
  deviceId: number;
  name?: string;
  productIdentifier?: string;
  status?: string;
  impact?: string;
  type?: string;
}

export interface SoftwarePatchInstallEntry {
  deviceId: number;
  name?: string;
  productIdentifier?: string;
  status?: string;
  impact?: string;
  installedAt?: string;
}

export interface DeviceHealthEntry {
  deviceId: number;
  health?: string;
  score?: number;
}

export interface AntivirusStatusEntry {
  deviceId: number;
  productName?: string;
  productState?: string;
  ts?: string;
}

export interface AntivirusThreatEntry {
  deviceId: number;
  name?: string;
  threatStatus?: string;
  foundDate?: string;
}

export interface OperatingSystemEntry {
  deviceId: number;
  name?: string;
  manufacturer?: string;
  architecture?: string;
  buildNumber?: string;
}

export interface ComputerSystemEntry {
  deviceId: number;
  name?: string;
  manufacturer?: string;
  model?: string;
  biosSerialNumber?: string;
}

export interface LoggedOnUserEntry {
  deviceId: number;
  userName?: string;
}

// ─── Policies ─────────────────────────────────────────────────────────────────

export interface Policy {
  id: number;
  name?: string;
  description?: string;
  nodeClass?: string;
  parentPolicyId?: number;
  enabled?: boolean;
}

export interface NodeRole {
  id: number;
  name?: string;
  nodeClass?: string;
}

export interface PolicyMapping {
  nodeRoleId: number;
  policyId: number;
}

// ─── Ticketing ────────────────────────────────────────────────────────────────

export interface TicketBoard {
  id: number;
  name?: string;
}

export interface TicketSummary {
  id: number;
  summary?: string;
  status?: string;
  severity?: string;
  type?: string;
  clientId?: number;
  nodeId?: number;
  assignedAppUserId?: number;
  createTime?: number;
  updateTime?: number;
  [key: string]: unknown;
}

export interface TicketForm {
  id: number;
  name?: string;
}

export interface TicketContact {
  uid?: string;
  name?: string;
  email?: string;
  clientId?: number;
}

export interface TicketLogEntry {
  id?: number;
  type?: string;
  createTime?: number;
  body?: string;
  public?: boolean;
  [key: string]: unknown;
}
