package providers

type ProviderInfo struct {
	Name     string
	Category string
}

type DANECapability struct {
	Name         string
	DANEInbound  bool
	DANEOutbound bool
	Reason       string
	Alternative  string
	Patterns     []string
}

type MonitoringProvider struct {
	Name         string
	Capabilities []string
}

type SPFFlatteningProvider struct {
	Name     string
	Patterns []string
}

type DynamicServiceProvider struct {
	Name     string
	Category string
}

type HostedDKIMProvider struct {
	Name     string
	Patterns []string
}

var CNAMEProviderMap = map[string]ProviderInfo{
	"shopify.com":             {Name: "Shopify", Category: "E-commerce"},
	"myshopify.com":           {Name: "Shopify", Category: "E-commerce"},
	"bigcommerce.com":         {Name: "BigCommerce", Category: "E-commerce"},
	"squarespace.com":         {Name: "Squarespace", Category: "Website"},
	"wixdns.net":              {Name: "Wix", Category: "Website"},
	"wix.com":                 {Name: "Wix", Category: "Website"},
	"wordpress.com":           {Name: "WordPress.com", Category: "Website"},
	"wpengine.com":            {Name: "WP Engine", Category: "Website"},
	"pantheonsite.io":         {Name: "Pantheon", Category: "Website"},
	"netlify.app":             {Name: "Netlify", Category: "Website"},
	"netlify.com":             {Name: "Netlify", Category: "Website"},
	"vercel.app":              {Name: "Vercel", Category: "Website"},
	"vercel-dns.com":          {Name: "Vercel", Category: "Website"},
	"webflow.io":              {Name: "Webflow", Category: "Website"},
	"ghost.io":                {Name: "Ghost", Category: "Website"},
	"cargo.site":              {Name: "Cargo", Category: "Website"},
	"strikingly.com":          {Name: "Strikingly", Category: "Website"},
	"hubspot.net":             {Name: "HubSpot", Category: "Marketing"},
	"hubspot.com":             {Name: "HubSpot", Category: "Marketing"},
	"hs-sites.com":            {Name: "HubSpot", Category: "Marketing"},
	"marketo.com":             {Name: "Marketo (Adobe)", Category: "Marketing"},
	"mktoweb.com":             {Name: "Marketo (Adobe)", Category: "Marketing"},
	"pardot.com":              {Name: "Pardot (Salesforce)", Category: "Marketing"},
	"mailchimp.com":           {Name: "Mailchimp", Category: "Marketing"},
	"mailgun.org":             {Name: "Mailgun", Category: "Email"},
	"sendgrid.net":            {Name: "SendGrid (Twilio)", Category: "Email"},
	"postmarkapp.com":         {Name: "Postmark", Category: "Email"},
	"mandrillapp.com":         {Name: "Mandrill (Mailchimp)", Category: "Email"},
	"zendesk.com":             {Name: "Zendesk", Category: "Support"},
	"zendeskhost.com":         {Name: "Zendesk", Category: "Support"},
	"freshdesk.com":           {Name: "Freshdesk", Category: "Support"},
	"freshservice.com":        {Name: "Freshservice", Category: "Support"},
	"intercom.io":             {Name: "Intercom", Category: "Support"},
	"helpscout.com":           {Name: "Help Scout", Category: "Support"},
	"helpscout.net":           {Name: "Help Scout", Category: "Support"},
	"salesforce.com":          {Name: "Salesforce", Category: "CRM"},
	"force.com":               {Name: "Salesforce", Category: "CRM"},
	"salesforceliveagent.com": {Name: "Salesforce", Category: "CRM"},
	"zoho.com":                {Name: "Zoho", Category: "CRM"},
	"zoho.eu":                 {Name: "Zoho", Category: "CRM"},
	"pipedrive.com":           {Name: "Pipedrive", Category: "CRM"},
	"cloudfront.net":          {Name: "AWS CloudFront", Category: "CDN"},
	"amazonaws.com":           {Name: "AWS", Category: "Cloud"},
	"awsglobalaccelerator.com": {Name: "AWS Global Accelerator", Category: "Cloud"},
	"elasticbeanstalk.com":    {Name: "AWS Elastic Beanstalk", Category: "Cloud"},
	"s3.amazonaws.com":        {Name: "AWS S3", Category: "Cloud"},
	"azurewebsites.net":       {Name: "Azure App Service", Category: "Cloud"},
	"azure-api.net":           {Name: "Azure API Management", Category: "Cloud"},
	"azurefd.net":             {Name: "Azure Front Door", Category: "CDN"},
	"azureedge.net":           {Name: "Azure CDN", Category: "CDN"},
	"trafficmanager.net":      {Name: "Azure Traffic Manager", Category: "Cloud"},
	"cloudapp.azure.com":      {Name: "Azure", Category: "Cloud"},
	"blob.core.windows.net":   {Name: "Azure Blob Storage", Category: "Cloud"},
	"windows.net":             {Name: "Azure", Category: "Cloud"},
	"googleapis.com":          {Name: "Google Cloud", Category: "Cloud"},
	"appspot.com":             {Name: "Google App Engine", Category: "Cloud"},
	"googleplex.com":          {Name: "Google", Category: "Cloud"},
	"run.app":                 {Name: "Google Cloud Run", Category: "Cloud"},
	"web.app":                 {Name: "Firebase Hosting", Category: "Cloud"},
	"firebaseapp.com":         {Name: "Firebase", Category: "Cloud"},
	"cdn.cloudflare.net":      {Name: "Cloudflare", Category: "CDN"},
	"cloudflare.net":          {Name: "Cloudflare", Category: "CDN"},
	"cdn77.org":               {Name: "CDN77", Category: "CDN"},
	"fastly.net":              {Name: "Fastly", Category: "CDN"},
	"edgekey.net":             {Name: "Akamai", Category: "CDN"},
	"akamaiedge.net":          {Name: "Akamai", Category: "CDN"},
	"akadns.net":              {Name: "Akamai", Category: "CDN"},
	"akamaized.net":           {Name: "Akamai", Category: "CDN"},
	"edgesuite.net":           {Name: "Akamai", Category: "CDN"},
	"stackpathdns.com":        {Name: "StackPath", Category: "CDN"},
	"stackpathcdn.com":        {Name: "StackPath", Category: "CDN"},
	"sucuri.net":              {Name: "Sucuri", Category: "Security"},
	"incapdns.net":            {Name: "Imperva (Incapsula)", Category: "Security"},
	"impervadns.net":          {Name: "Imperva", Category: "Security"},
	"heroku.com":              {Name: "Heroku", Category: "PaaS"},
	"herokuapp.com":           {Name: "Heroku", Category: "PaaS"},
	"fly.dev":                 {Name: "Fly.io", Category: "PaaS"},
	"render.com":              {Name: "Render", Category: "PaaS"},
	"onrender.com":            {Name: "Render", Category: "PaaS"},
	"railway.app":             {Name: "Railway", Category: "PaaS"},
	"deno.dev":                {Name: "Deno Deploy", Category: "PaaS"},
	"pages.dev":               {Name: "Cloudflare Pages", Category: "PaaS"},
	"workers.dev":             {Name: "Cloudflare Workers", Category: "PaaS"},
	"digitaloceanspaces.com":  {Name: "DigitalOcean Spaces", Category: "Cloud"},
	"ondigitalocean.app":      {Name: "DigitalOcean App Platform", Category: "PaaS"},
	"linode.com":              {Name: "Linode (Akamai)", Category: "Cloud"},
	"linodeobjects.com":       {Name: "Linode Object Storage", Category: "Cloud"},
	"hetzner.cloud":           {Name: "Hetzner", Category: "Cloud"},
	"ovh.net":                 {Name: "OVH", Category: "Cloud"},
	"rackcdn.com":             {Name: "Rackspace CDN", Category: "CDN"},
	"unbouncepages.com":       {Name: "Unbounce", Category: "Landing Pages"},
	"leadpages.net":           {Name: "Leadpages", Category: "Landing Pages"},
	"instapage.com":           {Name: "Instapage", Category: "Landing Pages"},
	"tawk.to":                 {Name: "Tawk.to", Category: "Live Chat"},
	"crisp.chat":              {Name: "Crisp", Category: "Live Chat"},
	"drift.com":               {Name: "Drift", Category: "Live Chat"},
	"livechat.com":            {Name: "LiveChat", Category: "Live Chat"},
	"statuspage.io":           {Name: "Atlassian Statuspage", Category: "Monitoring"},
	"betteruptime.com":        {Name: "Better Uptime", Category: "Monitoring"},
}

var DANEMXCapability = map[string]DANECapability{
	"microsoft365": {
		Name: "Microsoft 365", DANEInbound: false, DANEOutbound: false,
		Reason:      "Microsoft 365 does not support DANE for inbound mail. Microsoft uses its own certificate pinning mechanism.",
		Alternative: "MTA-STS",
		Patterns:    []string{"outlook.com", "microsoft.com", "protection.outlook.com"},
	},
	"google_workspace": {
		Name: "Google Workspace", DANEInbound: false, DANEOutbound: true,
		Reason:      "Google Workspace supports DANE for outbound mail verification but does not publish TLSA records for its MX hosts.",
		Alternative: "MTA-STS",
		Patterns:    []string{"google.com", "googlemail.com", "gmail-smtp-in.l.google.com"},
	},
	"postfix_default": {
		Name: "Self-Hosted (Postfix)", DANEInbound: true, DANEOutbound: true,
		Reason:   "Postfix supports DANE natively since version 2.11. Self-hosted servers can publish TLSA records.",
		Patterns: []string{},
	},
	"zoho": {
		Name: "Zoho Mail", DANEInbound: false, DANEOutbound: false,
		Reason:      "Zoho Mail does not publish DANE/TLSA records for its MX hosts.",
		Alternative: "MTA-STS",
		Patterns:    []string{"zoho.com", "zoho.eu", "zoho.in"},
	},
	"fastmail": {
		Name: "Fastmail", DANEInbound: true, DANEOutbound: true,
		Reason:   "Fastmail publishes DANE/TLSA records for its MX hosts and supports DNSSEC.",
		Patterns: []string{"fastmail.com", "messagingengine.com"},
	},
	"mimecast": {
		Name: "Mimecast", DANEInbound: false, DANEOutbound: false,
		Reason:      "Mimecast is a security gateway with shared MX infrastructure. It does not publish per-customer TLSA records.",
		Alternative: "MTA-STS",
		Patterns:    []string{"mimecast.com"},
	},
	"proofpoint": {
		Name: "Proofpoint", DANEInbound: false, DANEOutbound: false,
		Reason:      "Proofpoint is a security gateway with shared MX infrastructure. It does not publish per-customer TLSA records.",
		Alternative: "MTA-STS",
		Patterns:    []string{"pphosted.com", "ppe-hosted.com"},
	},
	"barracuda": {
		Name: "Barracuda", DANEInbound: false, DANEOutbound: false,
		Reason:      "Barracuda is a security gateway with shared MX infrastructure. It does not publish per-customer TLSA records.",
		Alternative: "MTA-STS",
		Patterns:    []string{"barracudanetworks.com"},
	},
	"icloud": {
		Name: "iCloud Mail", DANEInbound: false, DANEOutbound: false,
		Reason:      "Apple iCloud Mail does not publish TLSA records for its MX hosts.",
		Alternative: "MTA-STS",
		Patterns:    []string{"icloud.com"},
	},
	"yahoo": {
		Name: "Yahoo Mail", DANEInbound: false, DANEOutbound: false,
		Reason:      "Yahoo Mail does not publish TLSA records for its MX hosts.",
		Alternative: "MTA-STS",
		Patterns:    []string{"yahoodns.net"},
	},
}

var DMARCMonitoringProviders = map[string]MonitoringProvider{
	"agari.com":        {Name: "Agari", Capabilities: []string{"DMARC reporting", "DMARC enforcement"}},
	"dmarcian.com":     {Name: "dmarcian", Capabilities: []string{"DMARC reporting", "DMARC analytics"}},
	"ondmarc.com":      {Name: "Red Sift OnDMARC", Capabilities: []string{"DMARC reporting", "DMARC enforcement"}},
	"redsift.cloud":    {Name: "Red Sift OnDMARC", Capabilities: []string{"DMARC reporting", "DMARC enforcement"}},
	"valimail.com":     {Name: "Valimail", Capabilities: []string{"DMARC reporting", "DMARC enforcement", "SPF management"}},
	"postmarkapp.com":  {Name: "Postmark", Capabilities: []string{"DMARC reporting"}},
	"250ok.com":        {Name: "250ok (Validity)", Capabilities: []string{"DMARC reporting"}},
	"proofpoint.com":   {Name: "Proofpoint", Capabilities: []string{"DMARC reporting", "DMARC enforcement"}},
	"fraudmarc.com":    {Name: "Fraudmarc", Capabilities: []string{"DMARC reporting"}},
	"mxtoolbox.com":    {Name: "MXToolbox", Capabilities: []string{"DMARC reporting"}},
	"uriports.com":     {Name: "URIports", Capabilities: []string{"DMARC reporting", "TLS-RPT reporting"}},
	"easydmarc.com":    {Name: "EasyDMARC", Capabilities: []string{"DMARC reporting", "DMARC analytics"}},
	"sendmarc.com":     {Name: "Sendmarc", Capabilities: []string{"DMARC reporting", "DMARC enforcement"}},
	"report-uri.com":   {Name: "Report URI", Capabilities: []string{"DMARC reporting"}},
	"dmarc.report":     {Name: "DMARC Report", Capabilities: []string{"DMARC reporting"}},
	"dmarcadvisor.com": {Name: "DMARC Advisor", Capabilities: []string{"DMARC reporting", "DMARC analytics"}},
}

var SPFFlatteningProviders = []SPFFlatteningProvider{
	{Name: "AutoSPF", Patterns: []string{"_spf.autospf.com", "autospf.com"}},
	{Name: "dmarcian SPF Surveyor", Patterns: []string{"dmarcian.com"}},
	{Name: "EasyDMARC EasySPF", Patterns: []string{"easyspf.com", "easydmarc.com"}},
	{Name: "Mailhardener SPF Optimizer", Patterns: []string{"mailhardener.com"}},
	{Name: "Red Sift OnDMARC", Patterns: []string{"redsift.cloud", "ondmarc.com"}},
	{Name: "Valimail SPF", Patterns: []string{"valimail.com", "_spf.valimail.com"}},
}

var DynamicServicesProviders = map[string]DynamicServiceProvider{
	"dyn.com":           {Name: "Dyn (Oracle)", Category: "Dynamic DNS"},
	"dynect.net":        {Name: "Dyn (Oracle)", Category: "Dynamic DNS"},
	"no-ip.com":         {Name: "No-IP", Category: "Dynamic DNS"},
	"no-ip.org":         {Name: "No-IP", Category: "Dynamic DNS"},
	"no-ip.biz":         {Name: "No-IP", Category: "Dynamic DNS"},
	"changeip.com":      {Name: "ChangeIP", Category: "Dynamic DNS"},
	"afraid.org":        {Name: "FreeDNS", Category: "Dynamic DNS"},
	"duckdns.org":       {Name: "DuckDNS", Category: "Dynamic DNS"},
	"dynu.com":          {Name: "Dynu", Category: "Dynamic DNS"},
	"nsupdate.info":     {Name: "nsupdate.info", Category: "Dynamic DNS"},
}

var DynamicServicesZones = []string{
	"dyndns.org", "dyndns.com", "homeip.net", "dyn.com",
	"no-ip.com", "no-ip.org", "no-ip.biz", "noip.com",
	"ddns.net", "hopto.org", "zapto.org", "sytes.net",
	"ddns.me", "freedns.afraid.org",
	"duckdns.org", "dynu.com", "nsupdate.info",
	"changeip.com",
}

var HostedDKIMProviders = []HostedDKIMProvider{
	{Name: "dmarcian", Patterns: []string{"dmarcian.com"}},
	{Name: "Valimail", Patterns: []string{"valimail.com"}},
	{Name: "Red Sift OnDMARC", Patterns: []string{"redsift.cloud", "ondmarc.com"}},
	{Name: "Agari", Patterns: []string{"agari.com"}},
	{Name: "EasyDMARC", Patterns: []string{"easydmarc.com"}},
	{Name: "Sendmarc", Patterns: []string{"sendmarc.com"}},
}
