# pgcap

The PostgreSQL network traffic analyzer 

build 

```
sudo apt-get install libpcap-dev

git https://github.com/kshvakov/pgcap.git && cd pgcap

go build --ldflags '-extldflags "-static" -s' 
```

use 

```
pgcap -h
Usage of /pgcap:
  -bpf_filter string
         (default "tcp and port 5432")
  -device string
         (default "lo")
  -max_query_len int
         (default 2048)
  -query_filter string
        not case-sensitive
  -slow_query_time int
        in milliseconds


sudo pgcap -slow_query_time=1


-[ QUERY 0.094665 s]-:
select count(*) from auth.users ;


-[ QUERY 0.016246 s]-:
select count(*) from test.table;


-[ QUERY 0.136868 s]-:
REFRESH MATERIALIZED VIEW test.m_view
```