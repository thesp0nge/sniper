require "sniper/logger"
require "sniper/version"
require "sniper/host"

module Sniper

  def self.do_first_scan(ip) 
    Nmap::Program.sudo_scan do |nmap|
      nmap.syn_scan = true
      nmap.service_scan = true
      nmap.os_fingerprint = true
      nmap.xml = DISCOVERY_SCAN
      nmap.verbose = false
      nmap.quiet = true
      nmap.targets = ip
    end
  end

  def self.do_ssh_scan(ip, port)
    Nmap::Program.sudo_scan do |nmap|
      nmap.service_scan = true
      nmap.xml = SSH_SCAN
      nmap.verbose = false
      nmap.ports = port
      nmap.script ="ssh-hostkey.nse, ssh2-enum-algos.nse, sshv1.nse"
      nmap.quiet = true
      nmap.targets = ip
    end
  end

  def self.do_ftp_scan(ip, port)
    Nmap::Program.sudo_scan do |nmap|
      nmap.service_scan = true
      nmap.xml = FTP_SCAN
      nmap.verbose = false
      nmap.ports = port
      nmap.script ="ftp-anon, ftp-bounce, ftp-brute, ftp-libopie, ftp-proftpd-backdoor, ftp-vsftpd-backdoor, ftp-vuln-cve2010-4221, tftp-enum"
      nmap.quiet = true
      nmap.targets = ip
    end
  end

  # It must be really optimized
  def self.do_http_scan(ip, port)
    Nmap::Program.sudo_scan do |nmap|
      nmap.service_scan = true
      nmap.xml = HTTP_SCAN
      nmap.verbose = false
      nmap.ports = port
      # ls /usr/local/Cellar/nmap/7.40/share/nmap/scripts/*http* | cut -f 10 -d '/' | cut -f 1 -d '.' | tr '\n', ', '
      nmap.script ="http-adobe-coldfusion-apsa1301,http-affiliate-id,http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-auth-finder,http-auth,http-avaya-ipoffice-users,http-awstatstotals-exec,http-axis2-dir-traversal,http-backup-finder,http-barracuda-dir-traversal,http-brute,http-cakephp-version,http-chrono,http-cisco-anyconnect,http-coldfusion-subzero,http-comments-displayer,http-config-backup,http-cors,http-cross-domain-policy,http-csrf,http-date,http-default-accounts,http-devframework,http-dlink-backdoor,http-dombased-xss,http-domino-enum-passwords,http-drupal-enum-users,http-drupal-enum,http-enum,http-errors,http-exif-spider,http-favicon,http-feed,http-fetch,http-fileupload-exploiter,http-form-brute,http-form-fuzzer,http-frontpage-login,http-generator,http-git,http-gitweb-projects-enum,http-google-malware,http-grep,http-headers,http-huawei-hg5xx-vuln,http-icloud-findmyiphone,http-icloud-sendmsg,http-iis-short-name-brute,http-iis-webdav-vuln,http-internal-ip-disclosure,http-joomla-brute,http-litespeed-sourcecode-download,http-ls,http-majordomo2-dir-traversal,http-malware-host,http-mcmp,http-method-tamper,http-methods,http-mobileversion-checker,http-ntlm-info,http-open-proxy,http-open-redirect,http-passwd,http-php-version,http-phpmyadmin-dir-traversal,http-phpself-xss,http-proxy-brute,http-put,http-qnap-nas-info,http-referer-checker,http-rfi-spider,http-robots.txt,http-robtex-reverse-ip,http-robtex-shared-ns,http-server-header,http-shellshock,http-sitemap-generator,http-slowloris-check,http-slowloris,http-sql-injection,http-stored-xss,http-svn-enum,http-svn-info,http-title,http-tplink-dir-traversal,http-trace,http-traceroute,http-unsafe-output-escaping,http-useragent-tester,http-userdir-enum,http-vhosts,http-virustotal,http-vlcstreamer-ls,http-vmware-path-vuln,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3192,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-6786,http-vuln-cve2013-7091,http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-2129,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1427,http-vuln-cve2015-1635,http-vuln-misfortune-cookie,http-vuln-wnr1000-creds,http-waf-detect,http-waf-fingerprint,http-webdav-scan,http-wordpress-brute,http-wordpress-enum,http-wordpress-users,http-xssed,ip-https-discover,membase-http-info,riak-http-info"
      nmap.quiet = true
      nmap.targets = ip
    end

  end

  def read_xml_file(filename)
    str = ""

    Nmap::XML.new(SSH_SCAN) do |xml|
      xml.each_host do |host|
        host.scripts.each do |name,output|
          output.each_line { |line| str+="  #{line}" }
        end
        host.each_port do |port|
          puts "  [#{port.number}/#{port.protocol}]"
          port.scripts.each do |name,output|
            puts "    [#{name}]"
            output.each_line { |line| str+="      #{line}" }
          end
        end
      end
    end
    str
  end

  def self.do_report(host)
    str = "# Recon report for #{host.ip}\n"
    str +="-----------------------------\n"
    str += "\n## Hostname\n#{host.hostname}\n"
    str += "\n## OS\n#{host.os}\n"
    str += "\n## Services found\n"
    host.services.each do |s|
      str += "* #{s[:port]} (#{s[:service]})\n"
    end

    if File.exists?(FTP_SCAN)
      str += "\n## FTP"
      str += read_xml_file(FTP_SCAN)
    end
    if File.exists?(SSH_SCAN)
      str += "\n## SSH"
      str += read_xml_file(SSH_SCAN)
    end
    if File.exists?(HTTP_SCAN)
      str += "\n## HTTP"
      str += read_xml_file(HTTP_SCAN)
    end

    str += "\n\nGenerated by sniper v#{Sniper::VERSION} on #{Time.now.strftime("%d/%m/%Y@%H:%M:%S")}"
    puts str
  end
end
