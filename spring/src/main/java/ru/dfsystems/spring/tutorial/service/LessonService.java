package ru.dfsystems.spring.tutorial.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dfsystems.spring.tutorial.dao.InstrumentDaoImpl;
import ru.dfsystems.spring.tutorial.dao.InstrumentListDao;
import ru.dfsystems.spring.tutorial.dao.LessonDaoImpl;
import ru.dfsystems.spring.tutorial.dao.LessonListDao;
import ru.dfsystems.spring.tutorial.dto.lesson.LessonDto;
import ru.dfsystems.spring.tutorial.dto.lesson.LessonListDto;
import ru.dfsystems.spring.tutorial.dto.lesson.LessonParams;
import ru.dfsystems.spring.tutorial.generated.tables.daos.LessonToInstrumentDao;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Lesson;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.LessonToInstrument;
import ru.dfsystems.spring.tutorial.mapping.MappingService;

import java.util.List;

@Service
public class LessonService extends BaseService<LessonListDto, LessonDto, LessonParams, Lesson> {
    LessonToInstrumentDao lessonToInstrument;

    @Autowired
    public LessonService(LessonListDao lessonListDao, LessonDaoImpl lessonDao, MappingService mappingService) {
        super(mappingService, lessonListDao, lessonDao, LessonListDto.class, LessonDto.class, Lesson.class);
    }

    @Transactional
    public void putInstrument(Integer idd, Integer instrumentIdd) {
        LessonToInstrument link = new LessonToInstrument();
        link.setLessonIdd(idd);
        link.setInstrumentIdd(instrumentIdd);
        lessonToInstrument.insert(link);
    }
}
