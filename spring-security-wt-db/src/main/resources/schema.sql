create table if not exists  user (
  id int(11) not null auto_increment,
  username varchar(100) not null,
  password varchar(1024) not null,
  email varchar(1024) not null,
  enabled tinyint(4) not null,
  account_non_expired tinyint(4) not null,
  credentials_non_expired tinyint(4) not null,
  account_non_locked tinyint(4) not null,
  primary key (id),
  unique key username (username)
) engine=innodb ;

create table if not exists role (
  id int(11) not null auto_increment,
  name varchar(255) default null,
  primary key (id),
  unique key name (name)
) engine=innodb ;

create table if not exists  permission (
  id int(11) not null auto_increment,
  name varchar(255) default null,
  description varchar(255) default null,
  primary key (id),
  unique key name (name)
) engine=innodb default charset=utf8;

create table  if not exists permission_role (
  permission_id int(11) default null,
  role_id int(11) default null,
  key permission_id (permission_id),
  key role_id (role_id),
  constraint permission_role_fk_1 foreign key (permission_id) references permission (id),
  constraint permission_role_fk_2 foreign key (role_id) references role (id)
) engine=innodb default charset=utf8;

create table if not exists role_user (
  role_id int(11) default null,
  user_id int(11) default null,
  key role_id (role_id),
  key user_id (user_id),
  constraint role_user_fk_1 foreign key (role_id) references role (id),
  constraint role_user_fk_2 foreign key (user_id) references user (id)
) engine=innodb default charset=utf8;
