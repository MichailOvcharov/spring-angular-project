package ru.dfsystems.spring.tutorial.dao;

import org.jooq.DSLContext;
import org.springframework.stereotype.Repository;
import ru.dfsystems.spring.tutorial.generated.Sequences;
import ru.dfsystems.spring.tutorial.generated.tables.daos.TeacherDao;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Student;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Teacher;

import java.time.LocalDateTime;
import java.util.List;

import static ru.dfsystems.spring.tutorial.generated.tables.Teacher.TEACHER;

@Repository
public class TeacherDaoImpl extends TeacherDao implements BaseDao<Teacher> {
    private final DSLContext jooq;

    public TeacherDaoImpl(DSLContext jooq) {
        super(jooq.configuration());
        this.jooq = jooq;
    }

    @Override
    public Teacher getActiveByIdd(Integer idd) {
        return jooq.select(TEACHER.fields())
                .from(TEACHER)
                .where(TEACHER.IDD.eq(idd).and(TEACHER.DELETE_DATE.isNull()))
                .fetchOneInto(Teacher.class);
    }

    public List<Teacher> getHistory(Integer Idd) {
        return jooq.selectFrom(TEACHER)
                .where(TEACHER.IDD.eq(Idd))
                .fetchInto(Teacher.class);
    }

    @Override
    public Teacher create(Teacher teacher) {
        teacher.setId(jooq.nextval(Sequences.TEACHER_ID_SEQ));
        if (teacher.getIdd() == null ) {
            teacher.setIdd(teacher.getId());
        }
        teacher.setCreateDate(LocalDateTime.now());
        super.insert(teacher);
        return teacher;
    }

}
