import { kv } from '@vercel/kv';
import { NextResponse } from 'next/server';

// Ensure in-memory store initialized
if (!global._webhooksStore) {
  global._webhooksStore = {
    requests: {},
    configs: {},
    counts: {}
  };
}

export async function POST(req, { params }) {
  const resolvedParams = await params;
  const id = resolvedParams.id;

  try {
    const isKvConnected = !!process.env.KV_URL;

    if (isKvConnected) {
      await kv.del(`webhook:${id}:requests`);
      await kv.set(`webhook:${id}:total_count`, 0);
    } else {
      const store = global._webhooksStore;
      store.requests[id] = [];
      store.counts[id] = 0;
    }

    return NextResponse.json({
      success: true,
      message: 'Inspection logs cleared successfully'
    });

  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to clear logs', details: error.message },
      { status: 500 }
    );
  }
}
