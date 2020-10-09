package ru.dfsystems.spring.tutorial.dao;

import lombok.AllArgsConstructor;
import lombok.val;
import org.jooq.DSLContext;
import org.jooq.SelectSeekStepN;
import org.jooq.SortField;
import org.springframework.stereotype.Repository;
import ru.dfsystems.spring.tutorial.dto.Page;
import ru.dfsystems.spring.tutorial.dto.PageParams;
import ru.dfsystems.spring.tutorial.dto.student.StudentParams;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Student;
import ru.dfsystems.spring.tutorial.generated.tables.records.StudentRecord;

import java.util.ArrayList;
import java.util.List;

import static ru.dfsystems.spring.tutorial.generated.tables.Student.STUDENT;

@Repository
@AllArgsConstructor
public class StudentListDao implements BaseListDao<Student, StudentParams> {
    private final DSLContext jooq;

    public Page<Student> list(PageParams<StudentParams> pageParams) {
        final StudentParams params = pageParams.getParams() == null ? new StudentParams() : pageParams.getParams();
        val listQuery = getStudentSelect(params);

        val count = jooq.selectCount()
                .from(listQuery)
                .fetchOne(0, Long.class);

        List<Student> list = listQuery.offset(pageParams.getStart())
                .limit(pageParams.getPage())
                .fetchInto(Student.class);

        return new Page<>(list, count);

    }

    private SelectSeekStepN<StudentRecord> getStudentSelect(StudentParams params){
        var condition = STUDENT.DELETE_DATE.isNull();
        if (params.getFirstName() != null) {
            condition = condition.and(STUDENT.FIRST_NAME.like(params.getFirstName()));
        }
        if (params.getMiddleName() != null){
            condition = condition.and(STUDENT.MIDDLE_NAME.like(params.getMiddleName()));
        }
        if (params.getLastName() != null){
            condition = condition.and(STUDENT.LAST_NAME.like(params.getLastName()));
        }
        if (params.getPassport() != null){
            condition = condition.and(STUDENT.PASSPORT.like(params.getPassport()));
        }
        if (params.getStatus() != null){
            condition = condition.and(STUDENT.STATUS.like(params.getStatus()));
        }
        if (params.getBirthDateStart() != null && params.getBirthDateStart() != null){
            condition = condition.and(STUDENT.BIRTH_DATE.between(params.getBirthDateStart(), params.getBirthDateEnd()));
        }
        if (params.getCreateDateStart() != null && params.getCreateDateEnd() != null){
            condition = condition.and(STUDENT.CREATE_DATE.between(params.getCreateDateStart(), params.getCreateDateEnd()));
        }

        val sort = getOrderBy(params.getOrderBy(), params.getOrderDir());

        return jooq.selectFrom(STUDENT)
                .where(condition)
                .orderBy(sort);
    }

    private SortField[] getOrderBy(String orderBy, String orderDir) {
        val asc = orderDir == null || orderDir.equalsIgnoreCase("asc");

        if (orderBy == null){
            return asc
                    ? new SortField[]{STUDENT.IDD.asc()}
                    : new SortField[]{STUDENT.IDD.desc()};
        }

        val orderArray = orderBy.split(",");

        List<SortField> listSortBy = new ArrayList<>();
        for (val order: orderArray){
            if (order.equalsIgnoreCase("idd")){
                listSortBy.add(asc ? STUDENT.IDD.asc() : STUDENT.IDD.desc());
            }
            if (order.equalsIgnoreCase("firstName")){
                listSortBy.add(asc ? STUDENT.FIRST_NAME.asc() : STUDENT.FIRST_NAME.desc());
            }
            if (order.equalsIgnoreCase("middleName")){
                listSortBy.add(asc ? STUDENT.MIDDLE_NAME.asc() : STUDENT.MIDDLE_NAME.desc());
            }
            if (order.equalsIgnoreCase("lastName")){
                listSortBy.add(asc ? STUDENT.LAST_NAME.asc() : STUDENT.LAST_NAME.desc());
            }
            if (order.equalsIgnoreCase("passport")){
                listSortBy.add(asc ? STUDENT.PASSPORT.asc() : STUDENT.PASSPORT.desc());
            }
            if (order.equalsIgnoreCase("status")){
                listSortBy.add(asc ? STUDENT.STATUS.asc() : STUDENT.STATUS.desc());
            }
            if (order.equalsIgnoreCase("birthDate")){
                listSortBy.add(asc ? STUDENT.BIRTH_DATE.asc() : STUDENT.BIRTH_DATE.desc());
            }
            if (order.equalsIgnoreCase("createDate")){
                listSortBy.add(asc ? STUDENT.CREATE_DATE.asc() : STUDENT.CREATE_DATE.desc());
            }
        }

        return listSortBy.toArray(new SortField[0]);
    }

}
