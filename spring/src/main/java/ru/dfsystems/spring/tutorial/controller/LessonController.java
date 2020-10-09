package ru.dfsystems.spring.tutorial.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import ru.dfsystems.spring.tutorial.dto.Page;
import ru.dfsystems.spring.tutorial.dto.PageParams;
import ru.dfsystems.spring.tutorial.dto.lesson.LessonDto;
import ru.dfsystems.spring.tutorial.dto.lesson.LessonListDto;
import ru.dfsystems.spring.tutorial.dto.lesson.LessonParams;
import ru.dfsystems.spring.tutorial.dto.room.RoomDto;
import ru.dfsystems.spring.tutorial.dto.room.RoomListDto;
import ru.dfsystems.spring.tutorial.dto.room.RoomParams;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Lesson;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Room;
import ru.dfsystems.spring.tutorial.service.BaseService;
import ru.dfsystems.spring.tutorial.service.LessonService;

@RestController
@RequestMapping(value = "/lesson", produces = "application/json; charset=UTF-8")
public class LessonController extends BaseController<LessonListDto, LessonDto, LessonParams, Lesson> {
    private LessonService lessonService;

    @Autowired
    public LessonController(LessonService lessonService) {
        super(lessonService);
        this.lessonService = lessonService;
    }

    @PutMapping("/{idd}/instrument")
    public void putInstrument(@PathVariable("idd") Integer idd, @RequestBody Integer instrumentIdd) {
        lessonService.putInstrument(idd,  instrumentIdd);
    }
}
