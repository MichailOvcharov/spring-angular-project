package ru.dfsystems.spring.tutorial.dto.course;


import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.Setter;
import ru.dfsystems.spring.tutorial.dto.BaseDto;
import ru.dfsystems.spring.tutorial.dto.student.StudentListDto;
import ru.dfsystems.spring.tutorial.dto.teacher.TeacherListDto;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Student;


import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
public class CourseDto extends BaseDto<CourseHistoryDto> {
    private String        name;
    private String        description;

    private Integer       maxCountStudent;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm")
    private LocalDateTime startDate;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm")
    private LocalDateTime endDate;
    private String        status;

    private Integer       teacherIdd;
    // private TeacherListDto teacher;
    List<StudentListDto> students;
}
