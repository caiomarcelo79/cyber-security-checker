import { NextRequest, NextResponse } from "next/server";

function getBackendBase(): string {
  const envUrl = process.env.INTERNAL_API_URL || process.env.NEXT_PUBLIC_API_URL;
  if (envUrl && !envUrl.startsWith("/")) {
    return envUrl.replace(/\/api\/v1\/?$/, "");
  }
  return "http://backend:8000";
}

async function proxyRequest(
  request: NextRequest,
  context: { params: { path: string[] } }
) {
  const params = await context.params;
  const path = Array.isArray(params?.path) ? params.path.join("/") : "";
  const backendBase = getBackendBase();
  const targetUrl = new URL(`${backendBase}/api/v1/${path}`);
  targetUrl.search = request.nextUrl.search;

  const headers = new Headers();
  request.headers.forEach((val, key) => {
    const k = key.toLowerCase();
    if (k !== "host" && k !== "content-length") {
      headers.set(key, val);
    }
  });

  const method = request.method;
  const hasBody = !["GET", "HEAD"].includes(method);
  const body = hasBody ? await request.arrayBuffer() : undefined;

  try {
    const res = await fetch(targetUrl.toString(), {
      method,
      headers,
      body,
      redirect: "manual",
    });

    const responseHeaders = new Headers();
    res.headers.forEach((val, key) => {
      const k = key.toLowerCase();
      if (!["transfer-encoding", "content-encoding", "connection"].includes(k)) {
        responseHeaders.set(key, val);
      }
    });

    return new NextResponse(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers: responseHeaders,
    });
  } catch (err) {
    return NextResponse.json(
      {
        detail: "Erro ao comunicar com o backend de segurança.",
        error: err instanceof Error ? err.message : String(err),
      },
      { status: 502 }
    );
  }
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const PATCH = proxyRequest;
export const DELETE = proxyRequest;
export const HEAD = proxyRequest;
export const OPTIONS = proxyRequest;
