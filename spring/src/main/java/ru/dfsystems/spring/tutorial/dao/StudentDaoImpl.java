package ru.dfsystems.spring.tutorial.dao;

import org.jooq.DSLContext;
import org.springframework.stereotype.Repository;
import ru.dfsystems.spring.tutorial.generated.tables.daos.StudentDao;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Student;
import ru.dfsystems.spring.tutorial.generated.Sequences;

import java.time.LocalDateTime;
import java.util.List;

import static ru.dfsystems.spring.tutorial.generated.tables.Student.STUDENT;
import static ru.dfsystems.spring.tutorial.generated.tables.StudentToCourse.STUDENT_TO_COURSE;

@Repository
public class StudentDaoImpl extends StudentDao implements BaseDao<Student> {
    private final DSLContext jooq;

    public StudentDaoImpl(DSLContext jooq) {
        super(jooq.configuration());
        this.jooq = jooq;
    }

    public Student getActiveByIdd(Integer idd) {
        return jooq.select(STUDENT.fields())
                .from(STUDENT)
                .where(STUDENT.IDD.eq(idd).and(STUDENT.DELETE_DATE.isNull()))
                .fetchOneInto(Student.class);
    }

    public List<Student> getHistory(Integer idd) {
        return jooq.selectFrom(STUDENT)
                    .where(STUDENT.IDD.eq(idd))
                    .fetchInto(Student.class);
    }

    public Student create(Student student) {
        student.setId(jooq.nextval(Sequences.STUDENT_ID_SEQ));
        if (student.getIdd() == null ) {
            student.setIdd(student.getId());
        }
        student.setCreateDate(LocalDateTime.now());
        super.insert(student);
        return student;
    }

    public List<Student> getStudentByCourseIdd(Integer idd) {
        return jooq.select(STUDENT.fields())
                .from(STUDENT)
                .join(STUDENT_TO_COURSE)
                .on(STUDENT.IDD.eq(STUDENT_TO_COURSE.STUDENT_IDD))
                .where(STUDENT_TO_COURSE.COURSE_IDD.eq(idd))
                .fetchInto(Student.class);
    }

}
