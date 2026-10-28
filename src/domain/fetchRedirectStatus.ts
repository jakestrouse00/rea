/**
 * Fetch redirect statuses per WHATWG Fetch (the redirect status list:
 * 301, 302, 303, 307, 308). Single owner for redirect decisions.
 * 300/304/305/306 carry `Location` without being redirects — following them
 * would replace an observed failure with an unrelated document.
 * See https://fetch.spec.whatwg.org/#redirect-status
 */
export const isFetchRedirectStatus = (status: number): boolean =>
  status === 301 ||
  status === 302 ||
  status === 303 ||
  status === 307 ||
  status === 308;

/**
 * The method a followed redirect dispatches. 303 always becomes GET; 301/302
 * rewrite a POST to GET, other methods and 307/308 keep their method.
 */
export const redirectMethod = (status: number, method: string): string =>
  status === 303 || ((status === 301 || status === 302) && method === "POST")
    ? "GET"
    : method;
