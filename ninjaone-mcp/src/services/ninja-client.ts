import axios, { AxiosError, AxiosInstance } from "axios";
import { REGIONS, TOKEN_PATH, API_BASE_PATH, REQUEST_TIMEOUT_MS, Region } from "../constants.js";
import type { TokenResponse } from "../types.js";

// ─── Error Handling ───────────────────────────────────────────────────────────

export function handleApiError(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const axiosErr = error as AxiosError;
    if (axiosErr.response) {
      const status = axiosErr.response.status;
      const data = axiosErr.response.data as Record<string, unknown> | undefined;
      const msg = data?.message ?? data?.error ?? JSON.stringify(data);
      switch (status) {
        case 400:
          return `Error: Bad request — ${msg}. Check your parameters.`;
        case 401:
          return "Error: Unauthorized. Check your NINJAONE_CLIENT_ID and NINJAONE_CLIENT_SECRET.";
        case 403:
          return "Error: Permission denied. Ensure your API app has the required scopes (Monitoring/Management/Control).";
        case 404:
          return `Error: Resource not found. Verify the ID is correct.`;
        case 409:
          return `Error: Conflict — ${msg}.`;
        case 429:
          return "Error: Rate limit exceeded. Please wait before retrying.";
        case 500:
          return `Error: NinjaOne server error — ${msg}. Try again later.`;
        default:
          return `Error: API request failed with status ${status}: ${msg}`;
      }
    } else if (axiosErr.code === "ECONNABORTED") {
      return "Error: Request timed out. Check your network connection.";
    } else if (axiosErr.code === "ECONNREFUSED") {
      return "Error: Connection refused. Verify the NinjaOne region is correct.";
    }
  }
  return `Error: Unexpected error — ${error instanceof Error ? error.message : String(error)}`;
}

// ─── NinjaOne Client ──────────────────────────────────────────────────────────

export class NinjaOneClient {
  private readonly baseUrl: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly http: AxiosInstance;

  private accessToken: string | null = null;
  private tokenExpiresAt: number = 0;

  constructor(clientId: string, clientSecret: string, region: Region = "us") {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.baseUrl = REGIONS[region];

    this.http = axios.create({
      baseURL: this.baseUrl,
      timeout: REQUEST_TIMEOUT_MS,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
    });

    // Attach auth header on every request
    this.http.interceptors.request.use(async (config) => {
      const token = await this.getAccessToken();
      config.headers["Authorization"] = `Bearer ${token}`;
      return config;
    });

    // If a token was rejected (e.g. revoked or clock-skew expiry), clear the
    // cache and retry exactly once with a freshly minted token.
    this.http.interceptors.response.use(
      (response) => response,
      async (error) => {
        const config = error?.config as (import("axios").AxiosRequestConfig & { _retried?: boolean }) | undefined;
        if (
          axios.isAxiosError(error) &&
          error.response?.status === 401 &&
          config &&
          !config._retried
        ) {
          config._retried = true;
          this.accessToken = null;
          this.tokenExpiresAt = 0;
          const token = await this.getAccessToken();
          config.headers = config.headers ?? {};
          (config.headers as Record<string, string>)["Authorization"] = `Bearer ${token}`;
          return this.http.request(config);
        }
        return Promise.reject(error);
      }
    );
  }

  // ── Auth ──────────────────────────────────────────────────────────────────

  private async getAccessToken(): Promise<string> {
    const now = Date.now();
    // Refresh 60 s before expiry
    if (this.accessToken && now < this.tokenExpiresAt - 60_000) {
      return this.accessToken;
    }

    const params = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: this.clientId,
      client_secret: this.clientSecret,
      scope: "monitoring management control",
    });

    const response = await axios.post<TokenResponse>(
      `${this.baseUrl}${TOKEN_PATH}`,
      params.toString(),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: REQUEST_TIMEOUT_MS,
      }
    );

    this.accessToken = response.data.access_token;
    this.tokenExpiresAt = now + response.data.expires_in * 1000;
    return this.accessToken;
  }

  // ── Generic request helpers ───────────────────────────────────────────────

  async get<T>(path: string, params?: Record<string, unknown>): Promise<T> {
    const resp = await this.http.get<T>(`${API_BASE_PATH}${path}`, { params });
    return resp.data;
  }

  async post<T>(path: string, data?: unknown, params?: Record<string, unknown>): Promise<T> {
    const resp = await this.http.post<T>(`${API_BASE_PATH}${path}`, data, { params });
    return resp.data;
  }

  async patch<T>(path: string, data?: unknown): Promise<T> {
    const resp = await this.http.patch<T>(`${API_BASE_PATH}${path}`, data);
    return resp.data;
  }

  async put<T>(path: string, data?: unknown, params?: Record<string, unknown>): Promise<T> {
    const resp = await this.http.put<T>(`${API_BASE_PATH}${path}`, data, { params });
    return resp.data;
  }

  async delete<T>(path: string, params?: Record<string, unknown>): Promise<T> {
    const resp = await this.http.delete<T>(`${API_BASE_PATH}${path}`, { params });
    return resp.data;
  }
}

// ─── Singleton helper ─────────────────────────────────────────────────────────

let _client: NinjaOneClient | null = null;

export function getClient(): NinjaOneClient {
  if (!_client) {
    const clientId = process.env["NINJAONE_CLIENT_ID"];
    const clientSecret = process.env["NINJAONE_CLIENT_SECRET"];
    const region = (process.env["NINJAONE_REGION"] ?? "us") as Region;

    if (!clientId || !clientSecret) {
      throw new Error(
        "Missing NINJAONE_CLIENT_ID or NINJAONE_CLIENT_SECRET environment variables."
      );
    }

    if (!(region in REGIONS)) {
      throw new Error(`Invalid NINJAONE_REGION '${region}'. Must be one of: us, eu, oc`);
    }

    _client = new NinjaOneClient(clientId, clientSecret, region);
  }
  return _client;
}
