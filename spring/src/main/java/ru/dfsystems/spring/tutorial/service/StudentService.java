package ru.dfsystems.spring.tutorial.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dfsystems.spring.tutorial.dao.StudentDaoImpl;
import ru.dfsystems.spring.tutorial.dao.StudentListDao;
import ru.dfsystems.spring.tutorial.dto.student.StudentDto;
import ru.dfsystems.spring.tutorial.dto.student.StudentListDto;
import ru.dfsystems.spring.tutorial.dto.student.StudentParams;
import ru.dfsystems.spring.tutorial.generated.tables.daos.StudentToCourseDao;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Student;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.StudentToCourse;
import ru.dfsystems.spring.tutorial.mapping.MappingService;


@Service
public class StudentService  extends BaseService<StudentListDto, StudentDto, StudentParams, Student> {
    private StudentToCourseDao studentToCourseDao;

     @Autowired
     public StudentService(StudentListDao studentListDao, StudentDaoImpl studentDao, StudentToCourseDao studentToCourseDao, MappingService mappingService) {
         super(mappingService, studentListDao, studentDao, StudentListDto.class, StudentDto.class, Student.class);
         this.studentToCourseDao = studentToCourseDao;
     }

    @Transactional
    public void putCourse(Integer idd, Integer courseIdd) {
        StudentToCourse link = new StudentToCourse();
        link.setStudentIdd(idd);
        link.setCourseIdd(courseIdd);
        // потом переделать
        link.setSuccess(Boolean.TRUE);
        studentToCourseDao.insert(link);
    }

}
