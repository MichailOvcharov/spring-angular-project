package ru.dfsystems.spring.tutorial.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dfsystems.spring.tutorial.dao.InstrumentToRoomDaoImpl;
import ru.dfsystems.spring.tutorial.dao.RoomDaoImpl;
import ru.dfsystems.spring.tutorial.dao.RoomListDao;
import ru.dfsystems.spring.tutorial.dto.BaseListDto;
import ru.dfsystems.spring.tutorial.dto.instrument.InstrumentListDto;
import ru.dfsystems.spring.tutorial.dto.room.RoomDto;
import ru.dfsystems.spring.tutorial.dto.room.RoomListDto;
import ru.dfsystems.spring.tutorial.dto.room.RoomParams;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.InstrumentToRoom;
import ru.dfsystems.spring.tutorial.generated.tables.pojos.Room;
import ru.dfsystems.spring.tutorial.mapping.MappingService;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class RoomService extends BaseService<RoomListDto, RoomDto, RoomParams, Room> {
    private InstrumentToRoomDaoImpl instrumentToRoomDao;

    @Autowired
    public RoomService(RoomListDao roomListDao, RoomDaoImpl roomDao, InstrumentToRoomDaoImpl instrumentToRoomDao, MappingService mappingService) {
        super(mappingService, roomListDao, roomDao, RoomListDto.class, RoomDto.class, Room.class);
        this.instrumentToRoomDao = instrumentToRoomDao;
    }

    @Transactional
    public void putInstrument(Integer idd, Integer instrumentIdd) {
        InstrumentToRoom link = new InstrumentToRoom();
        link.setRoomIdd(idd);
        link.setInstrumentIdd(instrumentIdd);
        instrumentToRoomDao.insert(link);
    }

    @Override
    public RoomDto create(RoomDto dto) {
        RoomDto result = super.create(dto);
        mergeInstruments(dto.getIdd(), dto.getInstruments(), result.getInstruments());
        return get(result.getIdd());
    }

    @Override
    public RoomDto update(Integer idd, RoomDto dto) {
        RoomDto result = super.update(idd, dto);
        mergeInstruments(dto.getIdd(), dto.getInstruments(), result.getInstruments());
        return get(result.getIdd());
    }

    private void mergeInstruments(Integer roomIdd, List<InstrumentListDto> newInstruments, List<InstrumentListDto> oldInstruments) {
        List<Integer> newIdds = newInstruments.stream().map(BaseListDto::getIdd).collect(Collectors.toList());
        List<Integer> oldIdds = oldInstruments.stream().map(BaseListDto::getIdd).collect(Collectors.toList());

        List<Integer> iddsToBeDelete = oldIdds.stream().filter(o -> !newIdds.contains(o)).collect(Collectors.toList());
        List<Integer> iddsToBeAdd = newIdds.stream().filter(o -> !oldIdds.contains(o)).collect(Collectors.toList());

        instrumentToRoomDao.deleteByRoomAndInstrumentIdd(roomIdd, iddsToBeDelete);
        instrumentToRoomDao.createByRoomAndInstrumentIdd(roomIdd, iddsToBeAdd);
    }
}
