/**
 * ConnectWise Manage REST API types (subset).
 * Field names mirror the API exactly so JSON output is faithful.
 */

export interface CwRef {
  id: number;
  name?: string;
  identifier?: string;
  _info?: Record<string, string | undefined>;
}

export interface CwInfo {
  lastUpdated?: string;
  updatedBy?: string;
  dateEntered?: string;
  enteredBy?: string;
  [key: string]: string | undefined;
}

export interface CwError {
  code?: string;
  message?: string;
  errors?: Array<{ code?: string; message?: string; resource?: string; field?: string }>;
}

export interface Ticket {
  id: number;
  summary: string;
  recordType?: string;
  board?: CwRef;
  status?: CwRef;
  company?: CwRef;
  site?: CwRef;
  contact?: CwRef;
  contactName?: string;
  contactEmailAddress?: string;
  contactPhoneNumber?: string;
  type?: CwRef;
  subType?: CwRef;
  item?: CwRef;
  team?: CwRef;
  owner?: CwRef;
  priority?: CwRef;
  serviceLocation?: CwRef;
  source?: CwRef;
  agreement?: CwRef;
  severity?: string;
  impact?: string;
  requiredDate?: string;
  budgetHours?: number;
  actualHours?: number;
  approved?: boolean;
  closedFlag?: boolean;
  closedDate?: string;
  closedBy?: string;
  dateEntered?: string;
  enteredBy?: string;
  dateResponded?: string;
  dateResplan?: string;
  dateResolved?: string;
  resources?: string;
  parentTicketId?: number;
  hasChildTicket?: boolean;
  slaStatus?: string;
  customFields?: Array<{ id: number; caption?: string; type?: string; value?: unknown }>;
  _info?: CwInfo;
}

export interface TicketNote {
  id: number;
  ticketId: number;
  text?: string;
  detailDescriptionFlag?: boolean;
  internalAnalysisFlag?: boolean;
  resolutionFlag?: boolean;
  internalFlag?: boolean;
  externalFlag?: boolean;
  member?: CwRef;
  contact?: CwRef;
  createdBy?: string;
  dateCreated?: string;
  timeStart?: string;
  timeEnd?: string;
  _info?: CwInfo;
}

export interface Board {
  id: number;
  name: string;
  locationId?: number;
  businessUnitId?: number;
  inactiveFlag?: boolean;
  projectFlag?: boolean;
  _info?: CwInfo;
}

export interface BoardStatus {
  id: number;
  name: string;
  board?: CwRef;
  sortOrder?: number;
  displayOnBoard?: boolean;
  inactiveFlag?: boolean;
  closedStatus?: boolean;
  defaultFlag?: boolean;
  timeEntryNotAllowed?: boolean;
  _info?: CwInfo;
}

export interface BoardType {
  id: number;
  name: string;
  board?: CwRef;
  inactiveFlag?: boolean;
  defaultFlag?: boolean;
  _info?: CwInfo;
}

export interface Priority {
  id: number;
  name: string;
  color?: string;
  sortOrder?: number;
  defaultFlag?: boolean;
  _info?: CwInfo;
}

export interface TimeEntry {
  id: number;
  company?: CwRef;
  chargeToId?: number;
  chargeToType?: string;
  member?: CwRef;
  locationId?: number;
  businessUnitId?: number;
  workType?: CwRef;
  workRole?: CwRef;
  agreement?: CwRef;
  timeStart?: string;
  timeEnd?: string;
  actualHours?: number;
  hoursDeduct?: number;
  billableOption?: string;
  notes?: string;
  internalNotes?: string;
  addToDetailDescriptionFlag?: boolean;
  addToInternalAnalysisFlag?: boolean;
  addToResolutionFlag?: boolean;
  emailResourceFlag?: boolean;
  emailContactFlag?: boolean;
  emailCcFlag?: boolean;
  hoursBilled?: number;
  invoiceHours?: number;
  status?: string;
  ticket?: CwRef & { summary?: string };
  dateEntered?: string;
  enteredBy?: string;
  _info?: CwInfo;
}

export interface WorkType {
  id: number;
  name: string;
  billTime?: string;
  rateType?: string;
  rate?: number;
  inactiveFlag?: boolean;
  activityClass?: string;
  _info?: CwInfo;
}

export interface WorkRole {
  id: number;
  name: string;
  hourlyRate?: number;
  inactiveFlag?: boolean;
  _info?: CwInfo;
}

export interface Member {
  id: number;
  identifier: string;
  firstName?: string;
  lastName?: string;
  title?: string;
  officeEmail?: string;
  officePhone?: string;
  mobilePhone?: string;
  defaultEmail?: string;
  inactiveFlag?: boolean;
  licenseClass?: string;
  timeZone?: CwRef;
  defaultLocation?: CwRef;
  defaultDepartment?: CwRef;
  workRole?: CwRef;
  workType?: CwRef;
  _info?: CwInfo;
}

export interface Company {
  id: number;
  identifier: string;
  name: string;
  status?: CwRef;
  addressLine1?: string;
  addressLine2?: string;
  city?: string;
  state?: string;
  zip?: string;
  country?: CwRef;
  phoneNumber?: string;
  faxNumber?: string;
  website?: string;
  territory?: CwRef;
  market?: CwRef;
  accountNumber?: string;
  defaultContact?: CwRef;
  dateAcquired?: string;
  annualRevenue?: number;
  numberOfEmployees?: number;
  deletedFlag?: boolean;
  types?: CwRef[];
  site?: CwRef;
  _info?: CwInfo;
}

export interface Contact {
  id: number;
  firstName?: string;
  lastName?: string;
  company?: CwRef;
  site?: CwRef;
  title?: string;
  inactiveFlag?: boolean;
  defaultFlag?: boolean;
  communicationItems?: Array<{
    id?: number;
    type?: CwRef;
    value?: string;
    defaultFlag?: boolean;
    communicationType?: string;
  }>;
  types?: CwRef[];
  department?: CwRef;
  _info?: CwInfo;
}

export interface CompanySite {
  id: number;
  name: string;
  company?: CwRef;
  addressLine1?: string;
  addressLine2?: string;
  city?: string;
  state?: string;
  zip?: string;
  country?: CwRef;
  phoneNumber?: string;
  inactiveFlag?: boolean;
  primaryAddressFlag?: boolean;
  defaultShippingFlag?: boolean;
  defaultBillingFlag?: boolean;
  timeZone?: CwRef;
  _info?: CwInfo;
}

export interface Configuration {
  id: number;
  name: string;
  type?: CwRef;
  status?: CwRef;
  company?: CwRef;
  contact?: CwRef;
  site?: CwRef;
  locationId?: number;
  businessUnitId?: number;
  deviceIdentifier?: string;
  serialNumber?: string;
  modelNumber?: string;
  tagNumber?: string;
  purchaseDate?: string;
  installationDate?: string;
  warrantyExpirationDate?: string;
  vendorNotes?: string;
  notes?: string;
  macAddress?: string;
  lastLoginName?: string;
  billFlag?: boolean;
  backupSuccesses?: number;
  backupIncomplete?: number;
  backupFailed?: number;
  backupRestores?: number;
  lastBackupDate?: string;
  backupServerName?: string;
  backupBillableSpaceGb?: number;
  backupProtectedDeviceList?: string;
  backupYear?: number;
  backupMonth?: number;
  ipAddress?: string;
  defaultGateway?: string;
  osType?: string;
  osInfo?: string;
  cpuSpeed?: string;
  ram?: string;
  localHardDrives?: string;
  activeFlag?: boolean;
  managementLink?: string;
  remoteLink?: string;
  vendor?: CwRef;
  manufacturer?: CwRef;
  questions?: Array<{ questionId?: number; question?: string; answer?: unknown }>;
  _info?: CwInfo;
}

export interface ConfigurationType {
  id: number;
  name: string;
  inactiveFlag?: boolean;
  systemFlag?: boolean;
  _info?: CwInfo;
}

export interface SystemInfo {
  version?: string;
  isCloud?: boolean;
  serverTimeZone?: string;
  cloudRegion?: string;
  licenseBits?: unknown;
}

/** JSON Patch operation used by ConnectWise PATCH endpoints. */
export interface PatchOp {
  op: "replace" | "add" | "remove";
  path: string;
  value?: unknown;
}

/** Result of a paginated list call. */
export interface PagedResult<T> {
  items: T[];
  page: number;
  pageSize: number;
  count: number;
  has_more: boolean;
  next_page?: number;
  total?: number;
}
