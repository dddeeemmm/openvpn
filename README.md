openvpn
=========

    Install and configure OpenVPN-LDAP standalone or cluster service on Centos 7
    In finish, client.conf will be stored in /tmp/openvpn/client.conf

Requirements
------------

    # Ubuntu
    apt install openvpn-systemd-resolved
    sed -i 's/update-resolv-conf/update-systemd-resolved/g' /etc/openvpn/client.conf 
    sed -i '/down /etc/openvpn/update-systemd-resolved/a down-pre' /etc/openvpn/client.conf
    sed -i 'down-pre/a dhcp-option DOMAIN-ROUTE' /etc/openvpn/client.conf
    
    # Fedora
    cp /scripts/update-resolv-conf.fedora32 /etc/openvpn/update-resolv-conf
    uncomment in client.conf:
    script-security 2
    up /etc/openvpn/update-resolv-conf
    down /etc/openvpn/update-resolv-conf
    
    # Windows
    uncomment in client.conf:
    register-dns

Role Variables
--------------

    openvpn_master_name:            [default: first host in play_batch] Master hostname.
    
    openvpn_install:                [default: true] Install packages.
    openvpn_nat:                    [default: false] Add iptables rule for nat.
    openvpn_share_certs:            [autocheck] Copy certs from master to cluster. 
    openvpn_generate_certs:         [autocheck] Generate new certs.
    
    openvpn_server_cn:              [required] Server name.
    openvpn_server_network:         [default: 10.50.50.0 255.255.255.0] Client network.
    openvpn_server_port:            [default: 1194] Server port.
    openvpn_server_proto:           [default: udp] Server protocol.
    openvpn_server_register_dns:    [default: true] Add 'register-dns' option to client config.
    openvpn_server_dns_servers:     [not required] List of dns servers wich be configuret on client.
    openvpn_server_domain:          [not required] Search domain wich be configuret on client.
    openvpn_server_routes:          [not required] List of routes wich be configuret on client.
    openvpn_server_tls_ciphers:     [default: TLS-DHE-RSA-WITH-AES-256-CBC-SHA:
                                              TLS-DHE-RSA-WITH-AES-256-CBC-SHA256:
                                              TLS-DHE-RSA-WITH-AES-256-CBC-SHA256:
                                              TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA:
                                              TLS-DHE-RSA-WITH-AES-128-CBC-SHA] TLS cipher.
    openvpn_server_ciphers:         [default: AES-256-CBC] Client-Server cipher.
    openvpn_server_compression:     [default: true] Data compression.
    openvpn_server_verbosity:       [default: 3] Log level.
    
    openvpn_ldap_uri:               [required] The URI used to connect to the LDAP server
    openvpn_ldap_base_dn:           [required] The base DN used for LDAP lookups
    openvpn_ldap_bind_user_dn:      [not required] User DN to use for lookups
    openvpn_ldap_bind_user_pass:    [not required] The password for the bind user. 
    openvpn_ldap_filter:            [not required] A filter to apply to LDAP lookups.
    
    openvpn_iptables_cidr:          [required] For NAT configuration. 

Dependencies
------------

    ldap
    iptables

Example Playbook
----------------

    - hosts: openvpn
      vars:
        openvpn_master_name: vpn-1
        openvpn_server_cn: vpn.domain.org
        openvpn_server_dns_servers:
          - 192.168.0.1
          - 192.168.0.2
        openvpn_server_domain: domain.org
        openvpn_server_routes:
          - 192.168.0.1 255.255.255.0
        openvpn_ldap_uri: ldap://ipa.domain.org
        openvpn_ldap_base_dn: dc=domain,dc=org
        openvpn_ldap_bind_user_dn: uid=openvpn,cn=users,cn=accounts,dc=domain,dc=org
        openvpn_ldap_bind_user_pass: password
        openvpn_ldap_filter: (memberOf=cn=vpn,cn=groups,cn=accounts,dc=domain,dc=org)
        openvpn_iptables_cidr: 10.50.50.0/24
      roles:
        - { name: openvpn, become: yes, tags: openvpn }

License
-------

    MIT

Author Information
------------------

    Dmitrij Petrov
