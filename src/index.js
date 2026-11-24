export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return Response.json({
        ok: true,
        service: "STRADER",
        runtime: "cloudflare-worker",
        derivOAuth: "not-configured"
      }, {
        headers: {
          "Cache-Control": "no-store"
        }
      });
    }

    return env.ASSETS.fetch(request);
  }
};
