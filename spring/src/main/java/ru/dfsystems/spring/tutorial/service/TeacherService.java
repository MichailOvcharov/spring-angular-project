package ru.dfsystems.spring.tutorial.service;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import ru.dfsystems.spring.tutorial.dao.*;
import ru.dfsystems.spring.tutorial.dto.teacher.TeacherDto;
import ru.dfsystems.spring.tutorial.dto.teacher.TeacherListDto;
import ru.dfsystems.spring.tutorial.dto.teacher.TeacherParams;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.StudentToCourse;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Teacher;
import ru.dfsystems.spring.tutorial.mapping.MappingService;

@Service
public class TeacherService extends BaseService<TeacherListDto, TeacherDto, TeacherParams, Teacher> {

    @Autowired
    public TeacherService(TeacherListDao teacherListDao, TeacherDaoImpl teacherDao, MappingService mappingService) {
        super(mappingService, teacherListDao, teacherDao, TeacherListDto.class, TeacherDto.class, Teacher.class);
    }

    @Transactional
    public void putCourse(Integer idd, Integer courseIdd) {
        ;
    }
}