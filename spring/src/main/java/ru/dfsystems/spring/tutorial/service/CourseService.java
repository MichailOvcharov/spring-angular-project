package ru.dfsystems.spring.tutorial.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dfsystems.spring.tutorial.dao.BaseDao;
import ru.dfsystems.spring.tutorial.dao.BaseListDao;
import ru.dfsystems.spring.tutorial.dao.CourseDaoImpl;
import ru.dfsystems.spring.tutorial.dao.CourseListDao;
import ru.dfsystems.spring.tutorial.dto.course.CourseDto;
import ru.dfsystems.spring.tutorial.dto.course.CourseListDto;
import ru.dfsystems.spring.tutorial.dto.course.CourseParams;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.StudentToCourse;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Course;
import ru.dfsystems.spring.tutorial.mapping.BaseMapping;
import ru.dfsystems.spring.tutorial.mapping.MappingService;

@Service
public class CourseService extends BaseService<CourseListDto, CourseDto, CourseParams, Course> {
    @Autowired
    public CourseService(CourseListDao courseListDao, CourseDaoImpl courseDao, MappingService mappingService) {
        super(mappingService, courseListDao, courseDao, CourseListDto.class, CourseDto.class, Course.class);
    }
}
