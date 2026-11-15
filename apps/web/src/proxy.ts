// Next.js 16 request proxy (formerly middleware): a fast gate for the authenticated app area.
// It only checks that a session cookie is PRESENT; the API validates the session on every call and
// the shell redirects to /login on 401. Authorisation is never decided here.
import { NextResponse, type NextRequest } from "next/server";

export const SESSION_COOKIE = "novrsoc_session";

export function proxy(request: NextRequest) {
  if (request.cookies.has(SESSION_COOKIE)) return NextResponse.next();
  const url = request.nextUrl.clone();
  url.pathname = "/login";
  url.search = "";
  url.searchParams.set("next", request.nextUrl.pathname);
  return NextResponse.redirect(url);
}

export const config = { matcher: ["/app", "/app/:path*"] };
