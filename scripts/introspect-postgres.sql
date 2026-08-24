select json_build_object('tables', (
  select coalesce(json_agg(t order by t->>'name'), '[]'::json) from (
    select json_build_object(
      'name', c.relname,
      'columns', (
        select coalesce(json_agg(json_build_object(
          'name', a.attname,
          'udt', format_type(a.atttypid, null),
          'not_null', a.attnotnull,
          'has_default', a.atthasdef,
          'is_enum', (
            select coalesce(bool_or(x), false) from (
              select (tt.typtype='e') as x from pg_type tt where tt.oid=a.atttypid
              union all
              select (et.typtype='e') from pg_type tt2
                join pg_type et on et.oid=tt2.typelem
                where tt2.oid=a.atttypid and tt2.typelem<>0
            ) q),
          'enum_name', (
            select tn.typname from pg_type tt3
              join pg_type tn on tn.oid = (case when tt3.typelem<>0 then tt3.typelem else tt3.oid end)
              where tt3.oid=a.atttypid and tn.typtype='e'),
          'enum_members', (
            select coalesce(json_agg(en.enumlabel order by en.enumsortorder), '[]'::json)
            from pg_enum en where en.enumtypid = (
              select (case when tt4.typelem<>0 then tt4.typelem else tt4.oid end)
              from pg_type tt4 where tt4.oid=a.atttypid)),
          'unique_single', exists (
            select 1 from pg_index i where i.indrelid=c.oid and i.indisunique
              and i.indnatts=1 and not i.indisprimary and a.attnum = i.indkey[0]),
          'ord', a.attnum
        ) order by a.attnum), '[]'::json)
        from pg_attribute a where a.attrelid=c.oid and a.attnum>0 and not a.attisdropped),
      'unique_sets', (
        select coalesce(json_agg(cols), '[]'::json) from (
          select (select json_agg(att.attname order by k.ord)
                  from unnest(i.indkey::int[]) with ordinality k(attnum,ord)
                  join pg_attribute att on att.attrelid=c.oid and att.attnum=k.attnum) as cols
          from pg_index i where i.indrelid=c.oid and i.indisunique
            and not i.indisprimary and i.indnatts>1) q),
      'constraints', (
        select coalesce(json_agg(json_build_object(
          'type', con.contype,
          'cols', (select coalesce(json_agg(att.attname order by u.ord),'[]'::json)
                   from unnest(con.conkey) with ordinality u(attnum,ord)
                   join pg_attribute att on att.attrelid=con.conrelid and att.attnum=u.attnum),
          'ref_table', (select cc.relname from pg_class cc where cc.oid=con.confrelid),
          'ref_cols', (select coalesce(json_agg(att2.attname order by u2.ord),'[]'::json)
                       from unnest(con.confkey) with ordinality u2(attnum,ord)
                       join pg_attribute att2 on att2.attrelid=con.confrelid and att2.attnum=u2.attnum)
        )), '[]'::json)
        from pg_constraint con where con.conrelid=c.oid and con.contype in ('p','u','f'))
    ) as t
    from pg_class c join pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relkind='r' and c.relname <> '_prisma_migrations'
  ) s));
