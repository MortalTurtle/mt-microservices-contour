$TTL 86400
mt.ru.  IN      SOA     ns.mt.ru. root.localhost. (
                              3         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                          86400 )       ; Negative Cache TTL

mt.ru.  IN      NS      ns.mt.ru.
ns.mt.ru.      IN A    192.168.1.11
tvm.mt.ru.     IN A    192.168.1.12
gate.mt.ru.    IN A    192.168.1.13
auth.mt.ru.    IN A    192.168.1.14
