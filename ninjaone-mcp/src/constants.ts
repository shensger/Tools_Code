// API regions
export const REGIONS = {
  us: "https://app.ninjarmm.com",
  eu: "https://eu.ninjarmm.com",
  oc: "https://oc.ninjarmm.com",
} as const;

export type Region = keyof typeof REGIONS;

// Default values
export const DEFAULT_PAGE_SIZE = 25;
export const MAX_PAGE_SIZE = 200;
export const CHARACTER_LIMIT = 25000;
export const REQUEST_TIMEOUT_MS = 30000;

// OAuth token path
export const TOKEN_PATH = "/ws/oauth/token";
export const API_BASE_PATH = "/api/v2";
