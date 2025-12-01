$TTL    86400
mt.ru.        IN      SOA     ns_ext.mt.ru. root.localhost. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                          86400 )       ; Negative Cache TTL

mt.ru.        IN      NS      ns_ext.mt.ru.
ns_ext.mt.ru.   A       172.16.0.1
gate    IN      A       172.16.0.3
