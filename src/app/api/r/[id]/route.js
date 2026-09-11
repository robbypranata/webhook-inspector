import { kv } from '@vercel/kv';
import { NextResponse } from 'next/server';

// Initialize global in-memory store for local development if Vercel KV is not connected
if (!global._webhooksStore) {
  global._webhooksStore = {
    requests: {}, // { id: [...] }
    configs: {},  // { id: {...} }
    counts: {}    // { id: 0 }
  };
}

function generateRequestId() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

async function sendNotification(config, title, fields) {
  if (!config) return;
  
  // Format dynamic markdown for Telegram
  let telegramMessage = `*[Webhook Inspector]*\n*${title}*\n\n`;
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
        title: `Webhook Inspector: ${title}`,
        color: 0x3b82f6,
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

async function handle(req, { params }) {
  const resolvedParams = await params;
  const id = resolvedParams.id;

  try {
    // 1. Get client IP
    let ip = req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || '127.0.0.1';
    if (ip.includes(',')) {
      ip = ip.split(',')[0].trim();
    }

    // 2. Parse Query Parameters
    const urlObj = new URL(req.url);
    const query = {};
    urlObj.searchParams.forEach((value, key) => {
      if (query[key]) {
        if (Array.isArray(query[key])) {
          query[key].push(value);
        } else {
          query[key] = [query[key], value];
        }
      } else {
        query[key] = value;
      }
    });

    // 3. Parse Headers
    const headers = {};
    req.headers.forEach((value, key) => {
      headers[key] = value;
    });

    // 4. Parse Body
    let body = '';
    let bodyType = 'none';
    let size = 0;

    const hasBody = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && 
                    (req.headers.get('content-length') && parseInt(req.headers.get('content-length'), 10) > 0);

    if (hasBody) {
      try {
        const contentType = req.headers.get('content-type') || '';
        body = await req.text();
        size = body.length;

        if (contentType.includes('application/json')) {
          bodyType = 'json';
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          bodyType = 'form';
        } else if (contentType.includes('text/html') || contentType.includes('text/plain')) {
          bodyType = 'text';
        } else if (contentType.includes('multipart/form-data')) {
          bodyType = 'multipart';
        } else {
          bodyType = 'raw';
        }
      } catch (err) {
        body = `[Error reading body: ${err.message}]`;
        bodyType = 'error';
      }
    }

    // 5. Construct Request Log Object
    const webhookRequest = {
      requestId: generateRequestId(),
      method: req.method,
      path: urlObj.pathname,
      timestamp: new Date().toISOString(),
      ip,
      headers,
      query,
      body,
      bodyType,
      size
    };

    // 6. Save Request (Redis or In-Memory)
    const isKvConnected = !!process.env.KV_URL;
    
    if (isKvConnected) {
      const listKey = `webhook:${id}:requests`;
      await kv.lpush(listKey, JSON.stringify(webhookRequest));
      await kv.ltrim(listKey, 0, 49);
      await kv.incr(`webhook:${id}:total_count`);
    } else {
      // In-Memory Fallback
      const store = global._webhooksStore;
      if (!store.requests[id]) store.requests[id] = [];
      store.requests[id].unshift(webhookRequest);
      store.requests[id] = store.requests[id].slice(0, 50); // Keep last 50
      store.counts[id] = (store.counts[id] || 0) + 1;
    }

    // 7. Get Response Config (Redis or In-Memory)
    let savedConfig = null;
    if (isKvConnected) {
      savedConfig = await kv.get(`webhook:${id}:config`);
    } else {
      savedConfig = global._webhooksStore.configs[id] || null;
    }

    let responseStatus = 200;
    let responseHeaders = {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': '*'
    };
    let responseBody = JSON.stringify({ success: true, message: 'Webhook received successfully' });

    let configObj = null;
    if (savedConfig) {
      try {
        configObj = typeof savedConfig === 'string' ? JSON.parse(savedConfig) : savedConfig;
        
        if (configObj.status) responseStatus = parseInt(configObj.status, 10);
        if (configObj.contentType) responseHeaders['Content-Type'] = configObj.contentType;
        if (configObj.body !== undefined) {
          responseBody = configObj.body;
        }
      } catch (e) {
        console.error('Error parsing config:', e);
      }
    }

    // Trigger notification in the background asynchronously
    if (configObj && (configObj.telegramEnabled || configObj.discordEnabled)) {
      const notificationFields = {
        'Method': webhookRequest.method,
        'Path': webhookRequest.path,
        'IP Address': webhookRequest.ip,
        'Query Parameters': JSON.stringify(webhookRequest.query),
        'Payload Snippet': webhookRequest.body ? webhookRequest.body.substring(0, 400) : '[No Body]'
      };
      sendNotification(configObj, 'New OOB Webhook Callback Received!', notificationFields).catch(console.error);
    }

    if (req.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: responseHeaders
      });
    }

    return new Response(responseBody, {
      status: responseStatus,
      headers: responseHeaders
    });

  } catch (error) {
    console.error('Webhook ingestion error:', error);
    return NextResponse.json(
      { error: 'Internal Server Error', details: error.message },
      { status: 500 }
    );
  }
}

export {
  handle as GET,
  handle as POST,
  handle as PUT,
  handle as DELETE,
  handle as PATCH,
  handle as OPTIONS,
  handle as HEAD
};
