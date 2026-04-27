create table if not exists process_create(
    channel text not null,
    record_id integer not null,
    timestamp text,
    process_id integer,
    parent_process_id integer,
    image text,
    original_file_name text,
    command_line text,
    process_user text,
    logon_id text,
    integrity_level text,
    hashes text,
    parent_image text,
    parent_command_line text,
    primary key (channel, record_id)
);

create table if not exists network_connect(
    channel text not null,
    record_id integer not null,
    timestamp text,
    process_id integer,
    image text,
    process_user text,
    protocol text,
    initiated text,
    source_ip text,
    source_port text,
    destination_ip text,
    destination_hostname text,
    destination_port text,
    primary key (channel, record_id)
);

create table if not exists state(
    key text primary key,
    value text not null
);

create table if not exists alerts(
    id integer primary key autoincrement,
    rule_name text not null,
    mitre text not null,
    message text not null,
    severity text not null,
    timestamp text not null,
    channel text,
    record_id integer
);
