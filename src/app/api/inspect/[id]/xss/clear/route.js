import { kv } from '@vercel/kv';
import { NextResponse } from 'next/server';

export async function POST(request, { params }) {
  const resolvedParams = await params;
  const id = resolvedParams.id;

  if (!id) {
    return NextResponse.json({ success: false, error: 'Missing target ID' }, { status: 400 });
  }

  try {
    const isKvConnected = !!process.env.KV_URL;

    if (isKvConnected) {
      await kv.del(`xss:${id}:triggers`);
    } else {
      // In-memory fallback
      if (global._webhooksStore && global._webhooksStore.xss) {
        global._webhooksStore.xss[id] = [];
      }
    }

    return NextResponse.json({
      success: true,
      message: 'All Blind XSS triggers cleared successfully'
    });

  } catch (error) {
    console.error('Error clearing XSS triggers:', error);
    return NextResponse.json({ success: false, error: 'Internal Server Error' }, { status: 500 });
  }
}
