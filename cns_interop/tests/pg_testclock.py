"""A movable clock INSIDE a test PostgreSQL server, so a test can make the ledger database and a receiver disagree.

`clock_timestamp()` is shadowed by `testclock.clock_timestamp()`, a function in a schema that the database's search_path puts
before `pg_catalog`. Every statement the ledgers and stores run reads time through that name (the purge cutoff, lease
grants and takeovers, the time query a receiver's clock check makes), so moving this clock moves what the DATABASE says the
time is: shifted by any number of milliseconds forward or back, frozen at one instant, delayed past a statement timeout,
made to answer NULL from the Nth reading on, or made to answer NULL, a time before 1970 (negative ms), or infinity (a SQL error at the bigint cast).

What it is not: the operating-system clock of the database host. One machine has one clock, and PostgreSQL has no
setting that shifts `clock_timestamp()`, so this is the strongest available way to run the receiver against a database whose
own time is wrong. Test only; nothing in cns_interop or interop/node knows this schema exists.
"""

from __future__ import annotations

from typing import Optional

import psycopg

INSTALL = """
CREATE SCHEMA IF NOT EXISTS testclock;
CREATE TABLE IF NOT EXISTS testclock.state (one int PRIMARY KEY DEFAULT 1 CHECK (one = 1), shift_ms bigint NOT NULL DEFAULT 0,
    frozen_ms bigint, delay_ms bigint NOT NULL DEFAULT 0, mode text NOT NULL DEFAULT 'normal');
ALTER TABLE testclock.state ADD COLUMN IF NOT EXISTS null_from_call int, ADD COLUMN IF NOT EXISTS calls int NOT NULL DEFAULT 0;
INSERT INTO testclock.state DEFAULT VALUES ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION testclock.clock_timestamp() RETURNS timestamptz LANGUAGE plpgsql AS $$
DECLARE s testclock.state; n int;
BEGIN
  SELECT * INTO s FROM testclock.state;
  IF s.null_from_call IS NOT NULL THEN  -- opt in: count calls, answer NULL from the Nth on (the database goes bad mid-run)
    UPDATE testclock.state SET calls = calls + 1 RETURNING calls INTO n;
    IF n >= s.null_from_call THEN RETURN NULL; END IF;
  END IF;
  IF s.delay_ms > 0 THEN PERFORM pg_catalog.pg_sleep(s.delay_ms / 1000.0); END IF;
  IF s.mode = 'null' THEN RETURN NULL; END IF;
  IF s.mode = 'infinity' THEN RETURN 'infinity'::timestamptz; END IF;
  IF s.mode = 'year1900' THEN RETURN '1900-01-01 00:00:00+00'::timestamptz; END IF;
  IF s.frozen_ms IS NOT NULL THEN RETURN pg_catalog.to_timestamp(s.frozen_ms / 1000.0); END IF;
  RETURN pg_catalog.clock_timestamp() + (s.shift_ms * interval '1 millisecond');
END $$;
ALTER DATABASE postgres SET search_path = testclock, pg_catalog, public;
"""

MODES = ("normal", "null", "infinity", "year1900")


def install(dsn: str) -> None:
    """Put the movable clock in front of the real one for every NEW session of this database."""
    with psycopg.connect(dsn, autocommit=True) as db:
        db.execute(INSTALL)


def set_clock(dsn: str, *, shift_ms: int = 0, frozen_ms: Optional[int] = None, delay_ms: int = 0,
              mode: str = "normal", null_from_call: Optional[int] = None) -> None:
    """What the database answers from now on. The default arguments restore the real clock."""
    assert mode in MODES
    with psycopg.connect(dsn, autocommit=True) as db:
        db.execute("UPDATE testclock.state SET shift_ms = %s, frozen_ms = %s, delay_ms = %s, mode = %s, "
                   "null_from_call = %s, calls = 0", (shift_ms, frozen_ms, delay_ms, mode, null_from_call))


def real_now_ms(dsn: str) -> int:
    """The database's REAL clock, read past the shadow, so a test can place a decision relative to it."""
    with psycopg.connect(dsn, autocommit=True) as db:
        row = db.execute("SELECT (extract(epoch from pg_catalog.clock_timestamp()) * 1000)::bigint").fetchone()
        assert row is not None
        return int(row[0])
