create table if not exists process_create(
    channel text not null,
    record_id integer not null,
    timestamp text,
    process_id integer,
    parent_process_id integer,
    image text,
    command_line text,
    process_user text,
    logon_id text,
    integrity_level text,
    hashes text,
    parent_image text,
    parent_command_line text,
    primary key (channel, record_id)
);

create table if not exists state(
    key text primary key,
    value text not null
);
