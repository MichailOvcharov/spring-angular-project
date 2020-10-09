package ru.dfsystems.spring.tutorial.dao;

import lombok.AllArgsConstructor;
import lombok.val;
import org.jooq.DSLContext;
import org.jooq.SelectSeekStepN;
import org.jooq.SortField;
import org.springframework.stereotype.Repository;
import ru.dfsystems.spring.tutorial.dto.Page;
import ru.dfsystems.spring.tutorial.dto.PageParams;
import ru.dfsystems.spring.tutorial.dto.course.CourseParams;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Course;
import ru.dfsystems.spring.tutorial.generated.tables.records.CourseRecord;

import java.util.ArrayList;
import java.util.List;

import static ru.dfsystems.spring.tutorial.generated.tables.Course.COURSE;

@Repository
@AllArgsConstructor
public class CourseListDao implements  BaseListDao<Course, CourseParams> {
    private final DSLContext jooq;

    @Override
    public Page<Course> list(PageParams<CourseParams> pageParams) {
        final CourseParams params = pageParams.getParams() == null ? new CourseParams() : pageParams.getParams();
        val listQuery = getCourseSelect(params);

        val count = jooq.selectCount()
                .from(listQuery)
                .fetchOne(0, Long.class);

        List<Course> list = listQuery.offset(pageParams.getStart())
                .limit(pageParams.getPage())
                .fetchInto(Course.class);

        return new Page<>(list, count);
    }

    private SelectSeekStepN<CourseRecord> getCourseSelect(CourseParams params){
        var condition = COURSE.DELETE_DATE.isNull();
        if (params.getIdd() != null){
            condition = condition.and(COURSE.IDD.like(params.getIdd()));
        }
        if (params.getName() != null){
            condition = condition.and(COURSE.NAME.like(params.getName()));
        }
        if (params.getDescription() != null){
            condition = condition.and(COURSE.DESCRIPTION.like(params.getDescription()));
        }
        if (params.getTeacherIdd() != null){
            condition = condition.and(COURSE.TEACHER_IDD.like(params.getTeacherIdd()));
        }
        if (params.getMaxCountStudent() != null){
            condition = condition.and(COURSE.MAX_COUNT_STUDENT.like(params.getMaxCountStudent()));
        }
        if (params.getStartDateStart() != null && params.getStartDateEnd() != null){
            condition = condition.and(COURSE.START_DATE.between(params.getStartDateStart(), params.getStartDateEnd()));
        }
        if (params.getEndDateStart() != null && params.getEndDateEnd() != null){
            condition = condition.and(COURSE.END_DATE.between(params.getEndDateStart(), params.getEndDateEnd()));
        }
        if (params.getCreateDateStart() != null && params.getCreateDateEnd() != null){
            condition = condition.and(COURSE.CREATE_DATE.between(params.getCreateDateStart(), params.getCreateDateEnd()));
        }

        val sort = getOrderBy(params.getOrderBy(), params.getOrderDir());

        return jooq.selectFrom(COURSE)
                .where(condition)
                .orderBy(sort);
    }

    private SortField[] getOrderBy(String orderBy, String orderDir){
        val asc = orderDir == null || orderDir.equalsIgnoreCase("asc");

        if (orderBy == null){
            return asc
                    ? new SortField[]{COURSE.IDD.asc()}
                    : new SortField[]{COURSE.IDD.desc()};
        }

        val orderArray = orderBy.split(",");

        List<SortField> listSortBy = new ArrayList<>();
        for (val order: orderArray){
            if (order.equalsIgnoreCase("idd")){
                listSortBy.add(asc ? COURSE.IDD.asc() : COURSE.IDD.desc());
            }
            if (order.equalsIgnoreCase("block")){
                listSortBy.add(asc ? COURSE.NAME.asc() : COURSE.NAME.desc());
            }
            if (order.equalsIgnoreCase("description")){
                listSortBy.add(asc ? COURSE.DESCRIPTION.asc() : COURSE.DESCRIPTION.desc());
            }
            if (order.equalsIgnoreCase("teacherIdd")){
                listSortBy.add(asc ? COURSE.TEACHER_IDD.asc() : COURSE.TEACHER_IDD.desc());
            }
            if (order.equalsIgnoreCase("maxCountStudent")){
                listSortBy.add(asc ? COURSE.MAX_COUNT_STUDENT.asc() : COURSE.MAX_COUNT_STUDENT.desc());
            }
            if (order.equalsIgnoreCase("status")){
                listSortBy.add(asc ? COURSE.STATUS.asc() : COURSE.STATUS.desc());
            }
            if (order.equalsIgnoreCase("startDate")){
                listSortBy.add(asc ? COURSE.START_DATE.asc() : COURSE.START_DATE.desc());
            }
            if (order.equalsIgnoreCase("endDate")){
                listSortBy.add(asc ? COURSE.END_DATE.asc() : COURSE.END_DATE.desc());
            }
            if (order.equalsIgnoreCase("createDate")){
                listSortBy.add(asc ? COURSE.CREATE_DATE.asc() : COURSE.CREATE_DATE.desc());
            }
        }
        return listSortBy.toArray(new SortField[0]);
    }

}
