# explain-running-query
The script prints the execution plan of a running query in PostgreSQL.

It comes in handy if PostgreSQL gets stuck running a query.
Without the script, the best you can do is run [`EXPLAIN`](https://www.postgresql.org/docs/12/sql-explain.html) with the same query text.
Still, the plan doesn't have to be the same as the original, because PostgreSQL relies heavily on table statistics when planning a query and those might have changed since the original query started.

## Usage

```bash
sudo python3 explain_running_query.py PG_BACKEND_PID
```

`PG_BACKEND_PID` is a PID of PostgreSQL backend process executing the query. It can be obtained from `pid` column from [pg_stat_activity view](https://www.postgresql.org/docs/12/monitoring-stats.html#PG-STAT-ACTIVITY-VIEW) or from [pg_activity](https://pypi.org/project/pg_activity/) tool.

Root privileges are required to attach gdb to the running process.


## Example

```bash
$ psql -c "SELECT count(*) FROM generate_series(1, 200000000)" &
$ psql -p 5433 -c "SELECT pid, query FROM pg_stat_activity"
 pid  |                       query
------+----------------------------------------------------
 3587 | SELECT count(*) FROM generate_series(1, 200000000)
 3616 | SELECT pid, query FROM pg_stat_activity
(2 rows)

$ sudo python3 explain_running_query.py 3587
INFO: Waiting for low-level functions to finish. This may take a while.
Query Text: SELECT count(*) FROM generate_series(1, 200000000)
Plan:
Aggregate  (cost=2100000.00..2100000.01 rows=1 width=8)
  ->  Function Scan on generate_series  (cost=0.00..2000000.00 rows=200000000 width=0)
Detaching from program: /usr/lib/postgresql/12/bin/postgres, process 3587
[Inferior 1 (process 3587) detached]
```

## Requirements

- Python 3
- gdb >= 7.4
- PostgreSQL debug symbols (e.g. `yum install postgresql-12-debuginfo` on CentOS 7, `apt-get install postgresql-12-dbgsym` on Ubuntu Bionic)

Installing PostgreSQL debug symbols won't affect PostgreSQL performance.


## How it works

The script is based on existing [auto_explain](https://www.postgresql.org/docs/12/auto-explain.html) extension to PostgreSQL.
Technically, it attaches `gdb` (GNU's debugger) to a PostgreSQL backend process, waits for low-level functions to complete, and runs [internal PostgreSQL functions](https://github.com/postgres/postgres/blob/7559d8ebfa11d98728e816f6b655582ce41150f3/contrib/auto_explain/auto_explain.c#L382) to obtain the query plan.

## License

The script is distributed under [the MIT license](LICENSE).
