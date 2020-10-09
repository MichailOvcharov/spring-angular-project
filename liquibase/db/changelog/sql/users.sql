create table USERS (
    id serial primary key,
    idd int not null,
    login varchar(50),
    password varchar(50),
    student_idd int,
    teacher_idd int
)