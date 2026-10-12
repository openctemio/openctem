// Package software is the software catalog of RFC-066: product identity,
// version keys, the curated list of public products and the confidence of
// an observation.
//
// Design: docs/rfcs/RFC-066-inventory-vulnerability-matching.md.
package software

// Curated is one public product the platform knows by name. Its CPE
// identity is the one the vulnerability feed uses; AltCPE lists the other
// vendor:product pairs the feed has used for the same product (a vendor
// rename), and Names the names scanners report it under (lower case).
type Curated struct {
	Part       string
	Vendor     string
	Name       string
	CPEVendor  string
	CPEProduct string
	AltCPE     []string
	Names      []string
}

// CuratedProducts is the curated list. Every entry is a public product, so
// these rows are global catalog rows. Keep names lower case; the tests check
// that no name or CPE pair appears twice.
func CuratedProducts() []Curated {
	return curated
}

var curated = []Curated{
	{"a", "F5", "nginx", "f5", "nginx", []string{"nginx:nginx", "igor_sysoev:nginx"}, []string{"nginx"}},
	{"a", "Apache", "Apache HTTP Server", "apache", "http_server", nil, []string{"apache", "apache httpd", "httpd", "apache http server", "apache2"}},
	{"a", "OpenBSD", "OpenSSH", "openbsd", "openssh", nil, []string{"openssh"}},
	{"a", "Microsoft", "Internet Information Services", "microsoft", "internet_information_services", []string{"microsoft:iis"}, []string{"microsoft-iis", "iis", "microsoft iis", "microsoft iis httpd"}},
	{"a", "Apache", "Apache Tomcat", "apache", "tomcat", nil, []string{"apache tomcat", "tomcat", "apache tomcat/coyote jsp engine"}},
	{"a", "Eclipse", "Jetty", "eclipse", "jetty", []string{"mortbay:jetty"}, []string{"jetty"}},
	{"a", "PHP", "PHP", "php", "php", nil, []string{"php"}},
	{"a", "WordPress", "WordPress", "wordpress", "wordpress", nil, []string{"wordpress"}},
	{"a", "Drupal", "Drupal", "drupal", "drupal", nil, []string{"drupal"}},
	{"a", "Joomla", "Joomla!", "joomla", "joomla!", nil, []string{"joomla", "joomla!"}},
	{"a", "jQuery", "jQuery", "jquery", "jquery", nil, []string{"jquery"}},
	{"a", "jQuery", "jQuery UI", "jquery", "jquery_ui", nil, []string{"jquery ui"}},
	{"a", "Bootstrap", "Bootstrap", "getbootstrap", "bootstrap", nil, []string{"bootstrap"}},
	{"a", "AngularJS", "AngularJS", "angularjs", "angular.js", nil, []string{"angularjs"}},
	{"a", "Lodash", "Lodash", "lodash", "lodash", nil, []string{"lodash"}},
	{"a", "Moment.js", "Moment.js", "momentjs", "moment", nil, []string{"moment.js"}},
	{"a", "Exim", "Exim", "exim", "exim", nil, []string{"exim", "exim smtpd"}},
	{"a", "Postfix", "Postfix", "postfix", "postfix", nil, []string{"postfix", "postfix smtpd"}},
	{"a", "Sendmail", "Sendmail", "sendmail", "sendmail", nil, []string{"sendmail"}},
	{"a", "Beasts", "vsftpd", "beasts", "vsftpd", nil, []string{"vsftpd"}},
	{"a", "ProFTPD", "ProFTPD", "proftpd", "proftpd", nil, []string{"proftpd"}},
	{"a", "Pure-FTPd", "Pure-FTPd", "pureftpd", "pure-ftpd", nil, []string{"pure-ftpd", "pureftpd"}},
	{"a", "Oracle", "MySQL", "oracle", "mysql", []string{"mysql:mysql"}, []string{"mysql"}},
	{"a", "MariaDB", "MariaDB", "mariadb", "mariadb", nil, []string{"mariadb"}},
	{"a", "PostgreSQL", "PostgreSQL", "postgresql", "postgresql", nil, []string{"postgresql", "postgresql db"}},
	{"a", "Redis", "Redis", "redis", "redis", nil, []string{"redis", "redis key-value store"}},
	{"a", "MongoDB", "MongoDB", "mongodb", "mongodb", nil, []string{"mongodb"}},
	{"a", "Elastic", "Elasticsearch", "elastic", "elasticsearch", nil, []string{"elasticsearch", "elasticsearch rest api"}},
	{"a", "Elastic", "Kibana", "elastic", "kibana", nil, []string{"kibana"}},
	{"a", "Jenkins", "Jenkins", "jenkins", "jenkins", nil, []string{"jenkins"}},
	{"a", "GitLab", "GitLab", "gitlab", "gitlab", nil, []string{"gitlab"}},
	{"a", "Grafana", "Grafana", "grafana", "grafana", nil, []string{"grafana"}},
	{"a", "Atlassian", "Confluence", "atlassian", "confluence_server", []string{"atlassian:confluence_data_center", "atlassian:confluence"}, []string{"confluence", "atlassian confluence"}},
	{"a", "Atlassian", "Jira", "atlassian", "jira", []string{"atlassian:jira_server", "atlassian:jira_data_center"}, []string{"jira", "atlassian jira"}},
	{"a", "Microsoft", "Exchange Server", "microsoft", "exchange_server", nil, []string{"microsoft exchange server", "microsoft exchange"}},
	{"a", "lighttpd", "lighttpd", "lighttpd", "lighttpd", nil, []string{"lighttpd"}},
	{"a", "Caddy", "Caddy", "caddyserver", "caddy", nil, []string{"caddy"}},
	{"a", "HAProxy", "HAProxy", "haproxy", "haproxy", nil, []string{"haproxy"}},
	{"a", "Squid", "Squid", "squid-cache", "squid", nil, []string{"squid", "squid http proxy"}},
	{"a", "Node.js", "Node.js", "nodejs", "node.js", nil, []string{"node.js", "nodejs"}},
	{"a", "Express", "Express", "expressjs", "express", nil, []string{"express"}},
	{"a", "Django", "Django", "djangoproject", "django", nil, []string{"django"}},
	{"a", "Ruby on Rails", "Ruby on Rails", "rubyonrails", "rails", nil, []string{"ruby on rails", "rails"}},
	{"a", "Laravel", "Laravel", "laravel", "framework", nil, []string{"laravel"}},
	{"a", "OpenSSL", "OpenSSL", "openssl", "openssl", nil, []string{"openssl"}},
	{"a", "Dovecot", "Dovecot", "dovecot", "dovecot", nil, []string{"dovecot", "dovecot imapd", "dovecot pop3d"}},
	{"a", "ISC", "BIND", "isc", "bind", nil, []string{"isc bind"}},
	{"a", "Samba", "Samba", "samba", "samba", nil, []string{"samba", "samba smbd"}},
	{"a", "Traefik", "Traefik", "traefik", "traefik", nil, []string{"traefik"}},
	{"a", "Envoy", "Envoy", "envoyproxy", "envoy", nil, []string{"envoy"}},
	{"a", "Moodle", "Moodle", "moodle", "moodle", nil, []string{"moodle"}},
	{"a", "Magento", "Magento", "magento", "magento", nil, []string{"magento"}},
	{"a", "phpMyAdmin", "phpMyAdmin", "phpmyadmin", "phpmyadmin", nil, []string{"phpmyadmin"}},
	{"a", "Roundcube", "Roundcube Webmail", "roundcube", "webmail", nil, []string{"roundcube", "roundcube webmail"}},
	{"a", "Gitea", "Gitea", "gitea", "gitea", nil, []string{"gitea"}},
	{"a", "Nextcloud", "Nextcloud Server", "nextcloud", "nextcloud_server", nil, []string{"nextcloud"}},
	{"a", "Webmin", "Webmin", "webmin", "webmin", nil, []string{"webmin"}},
	{"a", "Apache", "Apache ActiveMQ", "apache", "activemq", nil, []string{"activemq", "apache activemq"}},
	{"a", "Apache", "Apache Solr", "apache", "solr", nil, []string{"solr", "apache solr"}},
	{"a", "Apache", "Apache Struts", "apache", "struts", nil, []string{"struts", "apache struts"}},
	{"a", "Apache", "Apache CouchDB", "apache", "couchdb", nil, []string{"couchdb", "apache couchdb"}},
	{"a", "Memcached", "Memcached", "memcached", "memcached", nil, []string{"memcached"}},
	{"a", "Zabbix", "Zabbix", "zabbix", "zabbix", nil, []string{"zabbix"}},
	{"a", "MinIO", "MinIO", "minio", "minio", nil, []string{"minio"}},
	{"a", "Red Hat", "Keycloak", "redhat", "keycloak", nil, []string{"keycloak"}},
	{"a", "HashiCorp", "Vault", "hashicorp", "vault", nil, []string{"hashicorp vault"}},
	{"a", "HashiCorp", "Consul", "hashicorp", "consul", nil, []string{"hashicorp consul"}},
	{"a", "VMware", "RabbitMQ", "vmware", "rabbitmq", []string{"pivotal_software:rabbitmq"}, []string{"rabbitmq"}},
	{"a", "VMware", "Spring Boot", "vmware", "spring_boot", nil, []string{"spring boot"}},
	{"a", "Kubernetes", "Kubernetes", "kubernetes", "kubernetes", nil, []string{"kubernetes"}},
	{"a", "SonarSource", "SonarQube", "sonarsource", "sonarqube", nil, []string{"sonarqube"}},
	{"a", "Ignite Realtime", "Openfire", "igniterealtime", "openfire", nil, []string{"openfire"}},
	{"a", "Liferay", "Liferay Portal", "liferay", "liferay_portal", nil, []string{"liferay", "liferay portal"}},
	{"a", "TYPO3", "TYPO3", "typo3", "typo3", nil, []string{"typo3", "typo3 cms"}},
	{"a", "PrestaShop", "PrestaShop", "prestashop", "prestashop", nil, []string{"prestashop"}},
	{"a", "Umbraco", "Umbraco CMS", "umbraco", "umbraco_cms", nil, []string{"umbraco"}},
	{"o", "Fortinet", "FortiOS", "fortinet", "fortios", nil, []string{"fortios"}},
	{"o", "Canonical", "Ubuntu Linux", "canonical", "ubuntu_linux", nil, []string{"ubuntu", "ubuntu linux"}},
	{"o", "Debian", "Debian Linux", "debian", "debian_linux", nil, []string{"debian", "debian linux"}},
}
