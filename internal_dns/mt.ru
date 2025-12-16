$TTL 86400
mt.ru.  IN      SOA     ns.mt.ru. root.localhost. (
                              3         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                          86400 )       ; Negative Cache TTL

mt.ru.              IN NS   ns.mt.ru.
ns.mt.ru.           IN A    192.168.1.200
service1.mt.ru.         IN A    192.168.1.11
service2.mt.ru.  IN A    192.168.1.12
certvault.mt.ru.    IN A    192.168.1.100
certservice.mt.ru.  IN A    192.168.1.101
tokenservice.mt.ru. IN A    192.168.1.102
