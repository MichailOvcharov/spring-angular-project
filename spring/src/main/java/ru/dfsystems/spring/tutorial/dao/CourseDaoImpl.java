package ru.dfsystems.spring.tutorial.dao;

import org.jooq.DSLContext;
import org.springframework.stereotype.Repository;
import ru.dfsystems.spring.tutorial.generated.Sequences;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Course;
import ru.dfsystems.spring.tutorial.generated.tables.daos.CourseDao;

import static ru.dfsystems.spring.tutorial.generated.tables.Course.COURSE;

import static ru.dfsystems.spring.tutorial.generated.tables.StudentToCourse.STUDENT_TO_COURSE;

import static ru.dfsystems.spring.tutorial.generated.tables.Teacher.TEACHER;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public class CourseDaoImpl extends CourseDao implements BaseDao<Course> {
    final DSLContext jooq;

    public CourseDaoImpl(DSLContext jooq) {
        super(jooq.configuration());
        this.jooq = jooq;
    }

    @Override
    public Course create(Course course) {
        course.setId(jooq.nextval(Sequences.COURSE_ID_SEQ));
        if (course.getIdd() == null) {
            course.setIdd(course.getId());
        }
        course.setCreateDate(LocalDateTime.now());
        super.insert(course);
        return course;
    }

    @Override
    public Course getActiveByIdd(Integer idd) {
        return jooq.select(COURSE.fields())
                .from(COURSE)
                .where(COURSE.IDD.eq(idd).and(COURSE.DELETE_DATE.isNull()))
                .fetchOneInto(Course.class);
    }

    public List<Course> getHistory(Integer idd) {
        return jooq.selectFrom(COURSE)
                .where(COURSE.IDD.eq(idd))
                .fetchInto(Course.class);
    }

    public List<Course> getCourseByStudentIdd(Integer idd) {
        return jooq.select(COURSE.fields())
                .from(COURSE)
                .join(STUDENT_TO_COURSE)
                .on(COURSE.IDD.eq(STUDENT_TO_COURSE.COURSE_IDD))
                .where(STUDENT_TO_COURSE.STUDENT_IDD.eq(idd))
                .and(COURSE.DELETE_DATE.isNull())
                .fetchInto(Course.class);
    }

    public List<Course> getCourseByTeacherIdd(Integer idd) {
        return jooq.select(COURSE.fields())
                .from(COURSE)
                .join(TEACHER)
                .on(TEACHER.IDD.eq(COURSE.TEACHER_IDD))
                .where(COURSE.TEACHER_IDD.eq(idd))
                .fetchInto(Course.class);
    }
}
