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

export async function GET(req, { params }) {
  const resolvedParams = await params;
  const id = resolvedParams.id;

  try {
    const isKvConnected = !!process.env.KV_URL;
    let requests = [];
    let totalCount = 0;
    let config = null;

    if (isKvConnected) {
      const rawRequests = await kv.lrange(`webhook:${id}:requests`, 0, -1) || [];
      requests = rawRequests.map(item => {
        try {
          return typeof item === 'string' ? JSON.parse(item) : item;
        } catch (e) {
          return { error: 'Failed to parse log item', raw: item };
        }
      });

      totalCount = await kv.get(`webhook:${id}:total_count`) || 0;

      const savedConfig = await kv.get(`webhook:${id}:config`);
      config = savedConfig 
        ? (typeof savedConfig === 'string' ? JSON.parse(savedConfig) : savedConfig)
        : null;

    } else {
      const store = global._webhooksStore;
      requests = store.requests[id] || [];
      totalCount = store.counts[id] || 0;
      config = store.configs[id] || null;
    }

    if (!config) {
      config = {
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, message: 'Webhook received successfully' })
      };
    }

    return NextResponse.json({
      success: true,
      id,
      totalCount: parseInt(totalCount, 10),
      config,
      requests
    });

  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to retrieve inspection data', details: error.message },
      { status: 500 }
    );
  }
}
