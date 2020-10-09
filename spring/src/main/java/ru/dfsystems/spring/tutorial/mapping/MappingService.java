package ru.dfsystems.spring.tutorial.mapping;

import lombok.AllArgsConstructor;
import org.modelmapper.Converter;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import ru.dfsystems.spring.tutorial.dao.*;
import ru.dfsystems.spring.tutorial.dto.course.CourseDto;
import ru.dfsystems.spring.tutorial.dto.course.CourseHistoryDto;
import ru.dfsystems.spring.tutorial.dto.course.CourseListDto;
import ru.dfsystems.spring.tutorial.dto.instrument.InstrumentDto;
import ru.dfsystems.spring.tutorial.dao.InstrumentDaoImpl;
import ru.dfsystems.spring.tutorial.dao.RoomDaoImpl;
import ru.dfsystems.spring.tutorial.dto.instrument.InstrumentHistoryDto;
import ru.dfsystems.spring.tutorial.dto.instrument.InstrumentListDto;
import ru.dfsystems.spring.tutorial.dto.lesson.LessonDto;
import ru.dfsystems.spring.tutorial.dto.lesson.LessonHistoryDto;
import ru.dfsystems.spring.tutorial.dto.room.RoomDto;
import ru.dfsystems.spring.tutorial.dto.room.RoomHistoryDto;
import ru.dfsystems.spring.tutorial.dto.student.StudentDto;
import ru.dfsystems.spring.tutorial.dto.student.StudentHistoryDto;
import ru.dfsystems.spring.tutorial.dto.student.StudentListDto;
import ru.dfsystems.spring.tutorial.dto.teacher.TeacherDto;
import ru.dfsystems.spring.tutorial.dto.teacher.TeacherHistoryDto;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.*;
import ru.dfsystems.spring.tutorial.dto.room.RoomListDto;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Instrument;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Room;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class MappingService implements BaseMapping {
    private ModelMapper modelMapper;
    private RoomDaoImpl roomDao;
    private InstrumentDaoImpl instrumentDao;

    private StudentDaoImpl studentDao;
    private CourseDaoImpl courseDao;

    private TeacherDaoImpl teacherDao;

    private LessonDaoImpl lessonDao;

    @PostConstruct
    public void init() {
        //  Дополнительные настройки.
        Converter<Integer, List<RoomHistoryDto>> roomHistory =
                context -> mapList(roomDao.getHistory(context.getSource()), RoomHistoryDto.class);
        Converter<Integer, List<InstrumentListDto>> instrumentList =
                context -> mapList(instrumentDao.getInstrumentsByRoomIdd(context.getSource()), InstrumentListDto.class);
        modelMapper.typeMap(Room.class, RoomDto.class)
                .addMappings(mapper -> mapper.using(roomHistory).map(Room::getIdd, RoomDto::setHistory))
                .addMappings(mapper -> mapper.using(instrumentList).map(Room::getIdd, RoomDto::setInstruments));

        Converter<Integer, List<StudentHistoryDto>> studentHistory =
                context -> mapList(studentDao.getHistory(context.getSource()), StudentHistoryDto.class);
        Converter<Integer, List<CourseListDto>> courseList =
                context -> mapList(courseDao.getCourseByStudentIdd(context.getSource()), CourseListDto.class);
        modelMapper.typeMap(Student.class, StudentDto.class)
                .addMappings(mapper -> mapper.using(studentHistory).map(Student::getIdd, StudentDto::setHistory))
                .addMappings(mapper -> mapper.using(courseList).map(Student::getIdd, StudentDto::setCourses));

        Converter<Integer, List<TeacherHistoryDto>> teacherHistory =
                context -> mapList(teacherDao.getHistory(context.getSource()), TeacherHistoryDto.class);
        modelMapper.typeMap(Teacher.class, TeacherDto.class)
                .addMappings(mapper -> mapper.using(teacherHistory).map(Teacher::getIdd, TeacherDto::setHistory))
                .addMappings(mapper -> mapper.using(courseList).map(Teacher::getIdd, TeacherDto::setCourses));

        Converter<Integer, List<InstrumentHistoryDto>> instrumentHistory =
                context -> mapList(instrumentDao.getHistory(context.getSource()), InstrumentHistoryDto.class);
        Converter<Integer, List<RoomListDto>> roomList =
                context -> mapList(roomDao.getRoomsByInstrumentIdd(context.getSource()), RoomListDto.class);
        modelMapper.typeMap(Instrument.class, InstrumentDto.class)
                .addMappings(mapper -> mapper.using(instrumentHistory).map(Instrument::getIdd, InstrumentDto::setHistory))
                .addMappings(mapper -> mapper.using(roomList).map(Instrument::getIdd, InstrumentDto::setRooms));

        Converter<Integer, List<CourseHistoryDto>> courseHistory =
                context -> mapList(courseDao.getHistory(context.getSource()), CourseHistoryDto.class);
        Converter<Integer, List<StudentListDto>> studentList =
                context -> mapList(studentDao.getStudentByCourseIdd(context.getSource()), StudentListDto.class);
        modelMapper.typeMap(Course.class, CourseDto.class)
                .addMappings(mapper -> mapper.using(courseHistory).map(Course::getIdd, CourseDto::setHistory))
                .addMappings(mapper -> mapper.using(studentList).map(Course::getIdd, CourseDto::setStudents));

        Converter<Integer, List<InstrumentListDto>> instrumentListLesson =
                context -> mapList(lessonDao.getInstrumentsByLessonIdd(context.getSource()), InstrumentListDto.class);
        modelMapper.typeMap(Lesson.class, LessonDto.class)
                .addMappings(mapper -> mapper.using(instrumentListLesson).map(Lesson::getId, LessonDto::setInstruments));

        Converter<Integer, List<LessonHistoryDto>> lessonHistory =
                context -> mapList(lessonDao.getHistory(context.getSource()), LessonHistoryDto.class);
        modelMapper.typeMap(Lesson.class, LessonDto.class)
                .addMappings(mapper -> mapper.using(lessonHistory).map(Lesson::getIdd, LessonDto::setHistory));
    }

    public <S, D> D map(S source, Class<D> clazz) {
        return modelMapper.map(source, clazz);
    }

    public <S, D> void map(S source, D dest) {
        modelMapper.map(source, dest);
    }

    public <S, D> List<D> mapList(List<S> sources, Class<D> clazz){
        return sources.stream()
                .map(s -> map(s, clazz))
                .collect(Collectors.toList());
    }
}
