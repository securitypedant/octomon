// octomon.dev: static site from ./website (served by the assets pipeline
// before this worker runs), /apt/* read from the octomon-apt R2 bucket —
// the Debian repository CI publishes into (.github/workflows/deb.yml) —
// and /edge, the one endpoint the octomon client itself calls.
//
// /edge privacy contract (see the site's /privacy page, which is the public
// face of this promise): the handler is pure request→response. It reads
// request.cf — facts Cloudflare computed before this code ran — and returns
// them TO THE CALLER. It stores nothing about the caller: no logging of
// request data, no KV/R2 writes, and the single Analytics Engine datapoint
// (when the EDGE_STATS binding exists) carries only octomon's own version
// string, the call's reason (one of three constant labels every client
// sends identically: start / netchange / refresh) and a count — no IP, no
// location, no user agent echo. Workers Logs stay disabled for this worker.

// The full octomon version ("0.8.1") out of our own client's User-Agent
// ("octomon/0.8.1 (…)"), "other" for anything else — browsers poking the
// endpoint out of curiosity get counted without being fingerprinted. The
// version names the software build, not the person running it.
function versionOf(ua) {
  const m = /^octomon\/(\d+\.\d+(?:\.\d+)?)/.exec(ua ?? "");
  return m ? m[1] : "other";
}

// The call's reason: three constant labels, identical across the whole
// fleet, so they identify nothing — but refresh calls tick every 15 minutes,
// which lets the /privacy graph estimate running instances without any
// identifier (refreshes per day ÷ 96 ≈ average octomons alive that day).
const WHYS = new Set(["start", "netchange", "refresh"]);

// The colo's own city ("MIA" → "Miami"): a snapshot of Cloudflare's PoP
// list (cloudflarestatus.com components, 341 codes). Static on purpose —
// the live locations endpoint stopped answering, the set changes rarely, and
// an unknown code simply shows as its bare IATA code in the client.
const COLO_CITY = {AAE:"Annaba",ABJ:"Abidjan",ABQ:"Albuquerque",ACC:"Accra",ACX:"Xingyi",ADB:"Izmir",ADD:"Addis Ababa",ADL:"Adelaide",AGR:"Agra",AIP:"Jalandhar",AKL:"Auckland",AKX:"Aktobe",ALA:"Almaty",ALG:"Algiers",AMD:"Ahmedabad",AMM:"Amman",AMS:"Amsterdam",ANC:"Anchorage",ARI:"Arica",ARN:"Stockholm",ARU:"Aracatuba",ASK:"Yamoussoukro",ASU:"Asunción",ATH:"Athens",ATL:"Atlanta",AUS:"Austin",AVA:"Anshun",BAH:"Manama",BAQ:"Barranquilla",BBI:"Bhubaneswar",BCN:"Barcelona",BDQ:"Jamnagar",BEG:"Belgrade",BEL:"Belém",BEY:"Beirut",BGI:"Bridgetown",BGR:"Bangor",BGW:"Baghdad",BKK:"Bangkok",BLR:"Bangalore",BNA:"Nashville",BNE:"Brisbane",BOD:"Bordeaux",BOG:"Bogotá",BOM:"Mumbai",BOS:"Boston",BRU:"Brussels",BSB:"Brasilia",BSR:"Basra",BTS:"Bratislava",BUD:"Budapest",BUF:"Buffalo",BWN:"Bandar Seri Begawan",CAI:"Cairo",CAN:"Guangzhou",CAW:"Campos dos Goytacazes",CBR:"Canberra",CCU:"Kolkata",CDG:"Paris",CEB:"Cebu",CFC:"Caçador",CGB:"Cuiaba",CGD:"Changde",CGK:"Jakarta",CGO:"Zhengzhou",CGP:"Chittagong",CGY:"Cagayan de Oro",CHC:"Christchurch",CJB:"Coimbatore",CKG:"Chongqing",CLE:"Cleveland",CLO:"Cali",CLT:"Charlotte",CMB:"Colombo",CMH:"Columbus",CNF:"Belo Horizonte",CNN:"Kannur",CNX:"Chiang Mai",COK:"Kochi",COR:"Córdoba",CPH:"Copenhagen",CPT:"Cape Town",CRK:"Tarlac City",CSX:"Changsha",CTU:"Chengdu",CVG:"Cincinnati",CWB:"Curitiba",CZL:"Constantine",CZX:"Changzhou",DAC:"Dhaka",DAD:"Da Nang",DAR:"Dar Es Salaam",DEL:"New Delhi",DEN:"Denver",DFW:"Dallas",DKR:"Dakar",DLA:"Douala",DLC:"Dalian",DME:"Moscow",DMM:"Dammam",DOH:"Doha",DPS:"Denpasar",DTW:"Detroit",DUB:"Dublin",DUR:"Durban",DUS:"Düsseldorf",DXB:"Dubai",DYU:"Dushanbe",EBB:"Kampala",EBL:"Erbil",EVN:"Yerevan",EWR:"Newark",EZE:"Buenos Aires",FCO:"Rome",FIH:"Kinshasa",FLN:"Florianopolis",FOC:"Fuzhou",FOR:"Fortaleza",FRA:"Frankfurt",FRU:"Bishkek",FSD:"Sioux Falls",FUK:"Fukuoka",FUO:"Foshan",GBE:"Gaborone",GDL:"Guadalajara",GEO:"Georgetown",GIG:"Rio de Janeiro",GND:"St. George's",GOT:"Gothenburg",GRU:"São Paulo",GUA:"Guatemala City",GUM:"Hagatna",GVA:"Geneva",GYD:"Baku",GYE:"Guayaquil",GYN:"Goiânia",HAK:"Haikou",HAM:"Hamburg",HAN:"Hanoi",HBA:"Hobart",HEL:"Helsinki",HFA:"Haifa",HGH:"Shaoxing",HKG:"Hong Kong",HNL:"Honolulu",HRE:"Harare",HYD:"Hyderabad",HYN:"Taizhou",IAD:"Ashburn",IAH:"Houston",ICN:"Seoul",IND:"Indianapolis",ISB:"Islamabad",IST:"Istanbul",ISU:"Sulaymaniyah",IXC:"Chandigarh",JAX:"Jacksonville",JDO:"Juazeiro do Norte",JED:"Jeddah",JIB:"Djibouti City",JNB:"Johannesburg",JOG:"Yogyakarta",JOI:"Joinville",JRG:"Sambalpur",JXG:"Jiaxing",KBP:"Kyiv",KCH:"Kuching",KEF:"Reykjavík",KGL:"Kigali",KHH:"Kaohsiung City",KHI:"Karachi",KHN:"Xinyu",KIN:"Kingston",KIV:"Chișinău",KIX:"Osaka",KJA:"Krasnoyarsk",KMG:"Kunming",KNU:"Kanpur",KTM:"Kathmandu",KUL:"Kuala Lumpur",KWE:"Guiyang",KWI:"Kuwait City",LAD:"Luanda",LAS:"Las Vegas",LAX:"Los Angeles",LCA:"Nicosia",LED:"Saint Petersburg",LHE:"Lahore",LHR:"London",LHW:"Lanzhou",LIM:"Lima",LIS:"Lisbon",LJU:"Ljubljana",LLK:"Astara",LLW:"Lilongwe",LOS:"Lagos",LPB:"La Paz",LUN:"Lusaka",LUX:"Luxembourg City",LYA:"Luoyang",LYS:"Lyon",MAA:"Chennai",MAD:"Madrid",MAN:"Manchester",MAO:"Manaus",MBA:"Mombasa",MCI:"Kansas City",MCT:"Muscat",MDE:"Medellín",MEL:"Melbourne",MEM:"Memphis",MEX:"Mexico City",MFM:"Macau",MIA:"Miami",MLA:"Santa Venera",MLE:"Malé",MLG:"Malang",MNL:"Manila",MPM:"Maputo",MRS:"Marseille",MRU:"Port Louis",MSP:"Minneapolis",MSQ:"Minsk",MUC:"Munich",MXP:"Milan",NAG:"Nagpur",NBO:"Nairobi",NJF:"Najaf",NOU:"Noumea",NQN:"Neuquén",NQZ:"Astana",NRT:"Tokyo",NVT:"Timbó",OKA:"Naha",OKC:"Oklahoma City",OMA:"Omaha",ORD:"Chicago",ORF:"Norfolk",ORN:"Oran",OSL:"Oslo",OTP:"Bucharest",OUA:"Ouagadougou",PAT:"Patna",PBH:"Thimphu",PBM:"Paramaribo",PDX:"Portland",PER:"Perth",PHL:"Philadelphia",PHX:"Phoenix",PIT:"Pittsburgh",PKX:"Langfang",PMO:"Palermo",PMW:"Palmas",PNH:"Phnom Penh",PNQ:"Pune",POA:"Porto Alegre",POS:"Port of Spain",PPT:"Tahiti",PRG:"Prague",PTY:"Panama City",QRO:"Queretaro",QWJ:"Americana",RAO:"Ribeirao Preto",RDU:"Durham",REC:"Recife",RIC:"Richmond",RIX:"Riga",RUH:"Riyadh",RUN:"Saint-Denis",SAN:"San Diego",SAP:"San Pedro Sula",SAT:"San Antonio",SCL:"Santiago",SDQ:"Santo Domingo",SEA:"Seattle",SFO:"San Francisco",SGN:"Ho Chi Minh City",SHA:"Shanghai",SIN:"Singapore",SJC:"San Jose",SJK:"São José dos Campos",SJO:"San José",SJP:"São José do Rio Preto",SJU:"San Juan",SJW:"Hengshui",SKG:"Thessaloniki",SKP:"Skopje",SLC:"Salt Lake City",SMF:"Sacramento",SOD:"Sorocaba",SOF:"Sofia",SSA:"Salvador",STI:"Santiago de los Caballeros",STL:"St. Louis",STR:"Stuttgart",SUV:"Suva",SYD:"Sydney",SZX:"Shenzhen",TAO:"Qingdao",TBS:"Tbilisi",TEN:"Tongren",TGU:"Tegucigalpa",TIA:"Tirana",TLH:"Tallahassee",TLL:"Tallinn",TLV:"Tel Aviv",TNA:"Jinan",TNR:"Antananarivo",TPA:"Tampa",TPE:"Taipei",TUN:"Tunis",TXL:"Berlin",TYN:"Yangquan",UDI:"Uberlândia",UDR:"Udaipur",UIO:"Quito",ULN:"Ulaanbaatar",URT:"Surat Thani",VCP:"Campinas",VIE:"Vienna",VIX:"Vitoria",VNO:"Vilnius",VTE:"Vientiane",WAW:"Warsaw",WDH:"Windhoek",WLG:"Wellington",WRO:"Wroclaw",XAP:"Chapeco",XFN:"Xiangyang",XIY:"Baoji",XNH:"Nasiriyah",YHZ:"Halifax",YUL:"Montréal",YVR:"Vancouver",YWG:"Winnipeg",YXE:"Saskatoon",YYC:"Calgary",YYZ:"Toronto",ZAG:"Zagreb",ZDM:"Ramallah",ZRH:"Zurich"};

// The newest released octomon version, read from GitHub's releases/latest
// redirect (the plain web endpoint, so no API rate limits) and memoized in
// the isolate for ten minutes. Deliberately NOT the Cache API: it served a
// value hours past its max-age here, and a module global cannot lie about
// its own age. Isolates recycle often, so worst case is a few extra
// redirect lookups. "" when unknowable.
let latestMemo = { v: "", at: 0 };

async function latestVersion() {
  if (Date.now() - latestMemo.at < 10 * 60 * 1000) return latestMemo.v;
  try {
    const r = await fetch(
      "https://github.com/securitypedant/octomon/releases/latest",
      { redirect: "manual" },
    );
    const m = /\/tag\/v?(\d+\.\d+\.\d+)$/.exec(r.headers.get("location") ?? "");
    latestMemo = { v: m ? m[1] : "", at: Date.now() };
  } catch {
    latestMemo = { v: "", at: Date.now() };
  }
  return latestMemo.v;
}

async function edgeAnswer(request, url, env, ctx) {
  const cf = request.cf ?? {};
  const body = {
    ip: request.headers.get("cf-connecting-ip") ?? "",
    asn: cf.asn ?? 0,
    isp: cf.asOrganization ?? "",
    colo: cf.colo ?? "",
    colo_city: COLO_CITY[cf.colo] ?? "",
    city: cf.city ?? "",
    country: cf.country ?? "",
    tcp_rtt_ms: cf.clientTcpRtt ?? null,
    http: cf.httpProtocol ?? "",
    tls: cf.tlsVersion ?? "",
    latest: await latestVersion(),
    ts: Math.floor(Date.now() / 1000),
  };
  if (env.EDGE_STATS) {
    // The whole record: version, reason, one count. This is the entire
    // input to the graph on /privacy.
    const whyParam = url.searchParams.get("why");
    ctx.waitUntil(
      Promise.resolve(
        env.EDGE_STATS.writeDataPoint({
          blobs: [
            versionOf(request.headers.get("user-agent")),
            WHYS.has(whyParam) ? whyParam : "",
          ],
          doubles: [1],
        }),
      ).catch(() => {}),
    );
  }
  return new Response(JSON.stringify(body) + "\n", {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

// The public aggregate behind the /privacy graph: daily request counts per
// octomon version for the last 30 days, queried from Analytics Engine and
// cached for an hour. Day buckets keep it coarse in time; the version names
// a public software build, not a person.
async function edgeStats(env) {
  if (!env.AE_QUERY_TOKEN || !env.CF_ACCOUNT_ID) {
    return new Response(JSON.stringify({ series: [] }) + "\n", {
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
  const sql = `
    SELECT toStartOfInterval(timestamp, INTERVAL '1' DAY) AS day,
           blob1 AS version,
           blob2 AS why,
           sum(_sample_interval * double1) AS calls
    FROM octomon_edge
    WHERE timestamp > now() - INTERVAL '30' DAY
    GROUP BY day, version, why
    ORDER BY day, version, why`;
  const resp = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${env.AE_QUERY_TOKEN}` },
      body: sql,
    },
  );
  if (!resp.ok) {
    return new Response(JSON.stringify({ series: [] }) + "\n", {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  }
  const data = await resp.json();
  const series = (data.data ?? []).map((r) => ({
    day: r.day,
    version: r.version,
    why: r.why ?? "",
    calls: Math.round(Number(r.calls) || 0),
  }));
  return new Response(JSON.stringify({ series }) + "\n", {
    headers: {
      "content-type": "application/json; charset=utf-8",
      // One aggregate an hour is plenty; the cache also shields the API
      // token path from being hammered through the public page.
      "cache-control": "public, max-age=3600",
    },
  });
}

const TYPES = {
  ".deb": "application/vnd.debian.binary-package",
  ".gz": "application/gzip",
  ".gpg": "application/pgp-keys",
  ".asc": "application/pgp-signature",
};

function contentType(key) {
  const dot = key.lastIndexOf(".");
  const ext = dot >= 0 ? key.slice(dot) : "";
  // Release/InRelease/Packages and anything unrecognised: plain text is what
  // apt expects to fetch, and octet-stream would still work.
  return TYPES[ext] ?? "text/plain; charset=utf-8";
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/edge") {
      return await edgeAnswer(request, url, env, ctx);
    }
    if (url.pathname === "/edge/stats") {
      return edgeStats(env);
    }
    if (!url.pathname.startsWith("/apt/")) {
      // Non-asset paths that reach the worker have no answer of their own, so
      // a browser gets the site's own 404 page rather than a bare string. The
      // /apt/ branch below deliberately keeps text/plain: apt is a package
      // manager, and an HTML error page only confuses it.
      const page = await env.ASSETS.fetch(new URL("/404.html", url));
      if (!page.ok) return new Response("not found\n", { status: 404 });
      return new Response(page.body, {
        status: 404,
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed\n", {
        status: 405,
        headers: { allow: "GET, HEAD" },
      });
    }
    // decodeURIComponent throws on a malformed escape ("/apt/%"), which would
    // surface as a 500. apt asking for nonsense deserves a 400, not an error
    // page that reads like the repository is broken.
    let key;
    try {
      key = decodeURIComponent(url.pathname.slice("/apt/".length));
    } catch {
      return new Response("bad request\n", { status: 400 });
    }
    if (!key) {
      return new Response("octomon apt repository\n", {
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
    const object = await env.APT.get(`apt/${key}`);
    if (!object) {
      return new Response("not found\n", { status: 404 });
    }
    const headers = {
      "content-type": contentType(key),
      "content-length": String(object.size),
      etag: object.httpEtag,
      // Indexes change on release; short TTL keeps `apt update` honest while
      // still absorbing fleets that update in lockstep. Pool files are
      // versioned by name and could cache longer, but one rule is simpler.
      "cache-control": "public, max-age=300",
    };
    if (request.method === "HEAD") {
      return new Response(null, { headers });
    }
    return new Response(object.body, { headers });
  },
};
