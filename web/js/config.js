// Fail2Ban Dashboard Configuration
const CONFIG = {
    logPath: '/var/log/fail2ban.log',
    refreshInterval: 300000,  // 5 minutes in milliseconds
    // Central service endpoint. The dashboard may be served by central.py or
    // by a reverse proxy on the same origin.
    dashboardApi: '/api/dashboard',
    hostsApi: '/api/hosts',
    maxRotatedFiles: 10,
    geoApiUrl: 'http://ip-api.com/json/',
    geoApiDelay: 1.4,  // seconds between API requests (45 req/min limit)
    serverLat: null,  // Manual override for server latitude (world-map arc target). null = use dashboard.json.server
    serverLon: null   // Manual override for server longitude (world-map arc target). null = use dashboard.json.server
};
