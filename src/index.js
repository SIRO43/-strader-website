const APP_ID = "353mT3gbscRELUZoEIEtE";
const REDIRECT_URI = "https://strader-website.ryansiro0.workers.dev/callback";
const AUTH_URL = "https://auth.deriv.com/oauth2/auth";
const TOKEN_URL = "https://auth.deriv.com/oauth2/token";

function cookieValue(request, name) {
  const header = request.headers.get("Cookie") || "";
  const part = header.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="));
  return part ? part.slice(name.length + 1) : null;
}
function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function randomString(length = 64) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return b64url(bytes);
}
async function challengeFor(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}
function htmlPage(title, message) {
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${title} | STRADER</title><body style="margin:0;background:#07111f;color:#f5f8fc;font:16px Arial;display:grid;min-height:100vh;place-items:center"><main style="max-width:560px;padding:32px;background:#101e30;border-radius:16px"><h1 style="color:#00d084">STRADER</h1><h2>${title}</h2><p>${message}</p><p><a style="color:#00d084" href="/">Return to STRADER</a></p></main></body></html>`, {headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}});
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return Response.json({ok:true,service:"STRADER",runtime:"cloudflare-worker",derivOAuth:"configured"}, {headers:{"Cache-Control":"no-store"}});
    }

    if (url.pathname === "/auth/deriv" && request.method === "GET") {
      const state = randomString(32);
      const verifier = randomString(64);
      const challenge = await challengeFor(verifier);
      const payload = btoa(JSON.stringify({state,verifier}));
      const auth = new URL(AUTH_URL);
      auth.searchParams.set("response_type","code");
      auth.searchParams.set("client_id",APP_ID);
      auth.searchParams.set("redirect_uri",REDIRECT_URI);
      auth.searchParams.set("scope","trade account_manage");
      auth.searchParams.set("state",state);
      auth.searchParams.set("code_challenge",challenge);
      auth.searchParams.set("code_challenge_method","S256");
      return new Response(null,{status:302,headers:{
        "Location":auth.toString(),
        "Set-Cookie":`strader_oauth=${payload}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`,
        "Cache-Control":"no-store"
      }});
    }

    if (url.pathname === "/callback" && request.method === "GET") {
      const oauthCookie = cookieValue(request,"strader_oauth");
      const clearState = "strader_oauth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax";
      const error = url.searchParams.get("error");
      if (error) return new Response(htmlPage("Sign-in cancelled","Deriv did not complete authorization. You can return and try again."),{headers:{"Set-Cookie":clearState}});
      const code = url.searchParams.get("code");
      const returnedState = url.searchParams.get("state");
      if (!oauthCookie || !code || !returnedState) {
        return new Response(htmlPage("Sign-in could not be verified","The authorization response was incomplete. Please start again from STRADER."),{status:400,headers:{"Set-Cookie":clearState}});
      }
      let saved;
      try { saved = JSON.parse(atob(oauthCookie)); } catch {
        return new Response(htmlPage("Sign-in could not be verified","Your temporary sign-in session was invalid. Please start again."),{status:400,headers:{"Set-Cookie":clearState}});
      }
      if (!saved.state || saved.state !== returnedState || !saved.verifier) {
        return new Response(htmlPage("Security check failed","The sign-in state did not match. Please start again."),{status:400,headers:{"Set-Cookie":clearState}});
      }
      const body = new URLSearchParams({
        grant_type:"authorization_code",
        client_id:APP_ID,
        code,
        code_verifier:saved.verifier,
        redirect_uri:REDIRECT_URI
      });
      let tokenResponse;
      try {
        const response = await fetch(TOKEN_URL,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});
        tokenResponse = await response.json();
        if (!response.ok || !tokenResponse.access_token) throw new Error("token exchange failed");
      } catch {
        return new Response(htmlPage("Deriv connection failed","STRADER could not complete the secure token exchange. Please try connecting again."),{status:502,headers:{"Set-Cookie":clearState}});
      }
      const maxAge = Math.max(60,Math.min(Number(tokenResponse.expires_in)||3600,2592000));
      const tokenCookie = `strader_session=${tokenResponse.access_token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
      return new Response(htmlPage("Deriv connected","Your Deriv authorization was received successfully. Live account information and trading features still need to be connected and tested."),{headers:{"Set-Cookie":[clearState,tokenCookie].join(", "),"Cache-Control":"no-store"}});
    }

    if (url.pathname === "/api/session" && request.method === "GET") {
      const token = cookieValue(request,"strader_session");
      return Response.json({authenticated:!!token,provider:token?"Deriv":null},{headers:{"Cache-Control":"no-store"}});
    }

    if (url.pathname === "/auth/logout" && request.method === "POST") {
      return new Response(null,{status:204,headers:{"Set-Cookie":"strader_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax","Cache-Control":"no-store"}});
    }

    return env.ASSETS.fetch(request);
  }
};
