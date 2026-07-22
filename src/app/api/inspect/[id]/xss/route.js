import { kv } from '@vercel/kv';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

export async function GET(request, { params }) {
  const resolvedParams = await params;
  const id = resolvedParams.id;

  if (!id) {
    return NextResponse.json({ success: false, error: 'Missing target ID' }, { status: 400 });
  }

  try {
    const isKvConnected = !!process.env.KV_URL;
    let triggers = [];

    if (isKvConnected) {
      const xssKey = `xss:${id}:triggers`;
      const data = await kv.lrange(xssKey, 0, -1);
      triggers = data.map(item => typeof item === 'string' ? JSON.parse(item) : item);
    } else {
      // In-memory fallback
      const store = global._webhooksStore;
      triggers = (store && store.xss && store.xss[id]) ? store.xss[id] : [];
    }

    return NextResponse.json({
      success: true,
      triggers,
      totalCount: triggers.length
    });

  } catch (error) {
    console.error('Error fetching XSS triggers:', error);
    return NextResponse.json({ success: false, error: 'Internal Server Error' }, { status: 500 });
  }
}
