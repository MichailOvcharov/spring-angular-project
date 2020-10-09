package ru.dfsystems.spring.tutorial.dao;

import org.jooq.DSLContext;
import org.springframework.stereotype.Repository;
import ru.dfsystems.spring.tutorial.generated.Sequences;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Lesson;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Instrument;
import ru.dfsystems.spring.tutorial.generated.tables.daos.LessonDao;

import static ru.dfsystems.spring.tutorial.generated.tables.Lesson.LESSON;

import static ru.dfsystems.spring.tutorial.generated.tables.LessonToInstrument.LESSON_TO_INSTRUMENT;

import static ru.dfsystems.spring.tutorial.generated.tables.Instrument.INSTRUMENT;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public class LessonDaoImpl extends LessonDao implements BaseDao<Lesson> {
    final DSLContext jooq;

    public LessonDaoImpl(DSLContext jooq) {
        super(jooq.configuration());
        this.jooq = jooq;
    }

    public List<Instrument> getInstrumentsByLessonIdd(Integer idd) {
        return jooq.select(INSTRUMENT.fields())
                .from(INSTRUMENT)
                .join(LESSON_TO_INSTRUMENT)
                .on(INSTRUMENT.IDD.eq(LESSON_TO_INSTRUMENT.INSTRUMENT_IDD))
                .where(LESSON_TO_INSTRUMENT.LESSON_IDD.eq(idd))
                .fetchInto(Instrument.class);
    }

//    public Lesson getById(Integer id) {
//        return jooq.select(LESSON.fields())
//                .from(LESSON)
//                .where(LESSON.ID.eq(id))
//                .fetchOneInto(Lesson.class);
//    }
    public Lesson getActiveByIdd(Integer idd) {
        return jooq.select(LESSON.fields())
                .from(LESSON)
                .where(LESSON.IDD.eq(idd).and(LESSON.DELETE_DATE.isNull()))
                .fetchOneInto(Lesson.class);
    }

    public List<Lesson> getHistory(Integer idd) {
        return jooq.selectFrom(LESSON)
                .where(LESSON.IDD.eq(idd))
                .fetchInto(Lesson.class);
    }

    public Lesson create(Lesson lesson) {
        lesson.setId(jooq.nextval(Sequences.LESSON_ID_SEQ));
        if (lesson.getIdd() == null) {
            lesson.setIdd(lesson.getId());
        }
        lesson.setCreateDate(LocalDateTime.now());
        super.insert(lesson);
        return lesson;
    }
}
