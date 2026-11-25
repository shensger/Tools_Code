/** Maximum characters returned in a single tool response before truncation kicks in. */
export const CHARACTER_LIMIT = 25000;

/** Default page size for list tools. ConnectWise allows up to 1000. */
export const DEFAULT_PAGE_SIZE = 25;
export const MAX_PAGE_SIZE = 1000;

/** Request timeout in milliseconds. */
export const REQUEST_TIMEOUT_MS = 30000;

export enum ResponseFormat {
  MARKDOWN = "markdown",
  JSON = "json",
}
