import { NextResponse } from 'next/server';

export async function POST(req, { params }) {
  try {
    const { targetUrl, method, headers, body } = await req.json();

    if (!targetUrl) {
      return NextResponse.json({ error: 'Target URL is required' }, { status: 400 });
    }

    const forwardHeaders = {};
    if (headers && typeof headers === 'object') {
      Object.keys(headers).forEach(key => {
        const lowerKey = key.toLowerCase();
        if (!['host', 'connection', 'content-length', 'content-encoding'].includes(lowerKey)) {
          forwardHeaders[key] = headers[key];
        }
      });
    }

    forwardHeaders['X-Forwarded-By'] = 'Antigravity Webhook Inspector';

    const fetchOptions = {
      method: method || 'POST',
      headers: forwardHeaders
    };

    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(fetchOptions.method) && body !== undefined) {
      fetchOptions.body = typeof body === 'object' ? JSON.stringify(body) : body;
    }

    const startTime = Date.now();
    let responseStatus = 0;
    let responseText = '';
    let responseHeaders = {};

    try {
      const response = await fetch(targetUrl, {
        ...fetchOptions,
        signal: AbortSignal.timeout(10000)
      });
      
      responseStatus = response.status;
      responseText = await response.text();
      
      response.headers.forEach((val, key) => {
        responseHeaders[key] = val;
      });

    } catch (fetchErr) {
      return NextResponse.json({
        success: false,
        error: 'Fetch operation failed',
        message: fetchErr.message,
        durationMs: Date.now() - startTime
      }, { status: 502 });
    }

    const durationMs = Date.now() - startTime;

    return NextResponse.json({
      success: true,
      status: responseStatus,
      durationMs,
      headers: responseHeaders,
      body: responseText.substring(0, 10000)
    });

  } catch (error) {
    return NextResponse.json(
      { error: 'Forwarding failed', details: error.message },
      { status: 500 }
    );
  }
}
