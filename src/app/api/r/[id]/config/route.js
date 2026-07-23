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

// GET custom response config
export async function GET(req, { params }) {
  const resolvedParams = await params;
  const id = resolvedParams.id;

  try {
    const isKvConnected = !!process.env.KV_URL;
    let savedConfig = null;

    if (isKvConnected) {
      savedConfig = await kv.get(`webhook:${id}:config`);
    } else {
      savedConfig = global._webhooksStore.configs[id] || null;
    }

    const defaultConfig = {
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ success: true, message: 'Webhook received successfully' })
    };

    if (!savedConfig) {
      return NextResponse.json(defaultConfig);
    }

    const config = typeof savedConfig === 'string' ? JSON.parse(savedConfig) : savedConfig;
    return NextResponse.json(config);

  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to retrieve configuration', details: error.message },
      { status: 500 }
    );
  }
}

// POST/SAVE custom response config
export async function POST(req, { params }) {
  const resolvedParams = await params;
  const id = resolvedParams.id;

  try {
    const { 
      status, 
      contentType, 
      body,
      telegramEnabled,
      telegramToken,
      telegramChatId,
      discordEnabled,
      discordWebhook
    } = await req.json();

    const parsedStatus = parseInt(status, 10);
    if (isNaN(parsedStatus) || parsedStatus < 100 || parsedStatus > 599) {
      return NextResponse.json({ error: 'Invalid HTTP Status Code' }, { status: 400 });
    }

    const config = {
      status: parsedStatus,
      contentType: contentType || 'application/json',
      body: body !== undefined ? body : '',
      telegramEnabled: !!telegramEnabled,
      telegramToken: telegramToken || '',
      telegramChatId: telegramChatId || '',
      discordEnabled: !!discordEnabled,
      discordWebhook: discordWebhook || ''
    };

    const isKvConnected = !!process.env.KV_URL;

    if (isKvConnected) {
      await kv.set(`webhook:${id}:config`, JSON.stringify(config));
    } else {
      global._webhooksStore.configs[id] = config;
    }

    return NextResponse.json({ success: true, message: 'Configuration saved successfully', config });

  } catch (error) {
    return NextResponse.json(
      { error: 'Failed to save configuration', details: error.message },
      { status: 500 }
    );
  }
}
