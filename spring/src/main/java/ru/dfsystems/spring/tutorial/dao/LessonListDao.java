package ru.dfsystems.spring.tutorial.dao;

import lombok.AllArgsConstructor;
import lombok.val;
import org.jooq.Condition;
import org.jooq.DSLContext;
import org.jooq.SelectSeekStepN;
import org.jooq.SortField;
import org.springframework.stereotype.Repository;
import ru.dfsystems.spring.tutorial.dto.Page;
import ru.dfsystems.spring.tutorial.dto.PageParams;
import ru.dfsystems.spring.tutorial.dto.lesson.LessonParams;
import ru.dfsystems.spring.tutorial.dto.room.RoomParams;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Lesson;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Room;
import ru.dfsystems.spring.tutorial.generated.tables.records.LessonRecord;

import java.util.ArrayList;
import java.util.List;

import static ru.dfsystems.spring.tutorial.generated.tables.Instrument.INSTRUMENT;
import static ru.dfsystems.spring.tutorial.generated.tables.Lesson.LESSON;

@Repository
@AllArgsConstructor
public class LessonListDao implements BaseListDao<Lesson, LessonParams> {
    private final DSLContext jooq;

    public Page<Lesson> list(PageParams<LessonParams> pageParams) {
        final LessonParams params = pageParams.getParams() == null ? new LessonParams() : pageParams.getParams();
        val listQuery = getLessonSelect(params);

        val count = jooq.selectCount()
                .from(listQuery)
                .fetchOne(0, Long.class);

        List<Lesson> list = listQuery.offset(pageParams.getStart())
                .limit(pageParams.getPage())
                .fetchInto(Lesson.class);

        return new Page<>(list, count);
    }

    private SelectSeekStepN<LessonRecord> getLessonSelect(LessonParams params){
        var condition = LESSON.DELETE_DATE.isNull();
        if (params.getIdd() != null){
            condition = condition.and(LESSON.IDD.like(params.getIdd()));
        }
        if (params.getName() != null){
            condition = condition.and(LESSON.NAME.like(params.getName()));
        }
        if (params.getDescription() != null){
            condition = condition.and(LESSON.DESCRIPTION.like(params.getDescription()));
        }
        if (params.getLessonDateStartPrior() != null && params.getLessonDateStartLater() != null){
            condition = condition.and(LESSON.LESSON_DATE_START.between(params.getLessonDateStartPrior(), params.getLessonDateStartLater()));
        }
        if (params.getLessonDateEndPrior() != null && params.getLessonDateStartLater() != null){
            condition = condition.and(LESSON.LESSON_DATE_END.between(params.getLessonDateEndPrior(), params.getLessonDateEndLater()));
        }
        val sort = getOrderBy(params.getOrderBy(), params.getOrderDir());

        return jooq.selectFrom(LESSON)
                .where(condition)
                .orderBy(sort);
    }

    private SortField[] getOrderBy(String orderBy, String orderDir){
        val asc = orderDir == null || orderDir.equalsIgnoreCase("asc");

        if (orderBy == null){
            return asc
                    ? new SortField[]{LESSON.IDD.asc()}
                    : new SortField[]{LESSON.IDD.desc()};
        }

        val orderArray = orderBy.split(",");

        List<SortField> listSortBy = new ArrayList<>();
        for (val order: orderArray){
            if (order.equalsIgnoreCase("name")){
                listSortBy.add(asc ? LESSON.NAME.asc() : LESSON.NAME.desc());
            }
            if (order.equalsIgnoreCase("description")){
                listSortBy.add(asc ? LESSON.DESCRIPTION.asc() : LESSON.DESCRIPTION.desc());
            }
            if (order.equalsIgnoreCase("lessonDateStart")){
                listSortBy.add(asc ? LESSON.LESSON_DATE_START.asc() : LESSON.LESSON_DATE_START.desc());
            }
            if (order.equalsIgnoreCase("lessonDateEnd")){
                listSortBy.add(asc ? LESSON.LESSON_DATE_END.asc() : LESSON.LESSON_DATE_END.desc());
            }
        }

        return listSortBy.toArray(new SortField[0]);
    }
}
